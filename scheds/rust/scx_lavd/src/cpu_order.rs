// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::Result;
use combinations::Combinations;
use itertools::iproduct;
use log::debug;
use log::warn;
use scx_utils::CoreType;
use scx_utils::Cpumask;
use scx_utils::EnergyModel;
use scx_utils::PerfDomain;
use scx_utils::PerfState;
use scx_utils::Topology;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::fmt;
use scx_utils::NR_CPU_IDS;

#[derive(Debug, Clone)]
pub struct CpuId {
    // - *_adx: an absolute index within a system scope
    // - *_rdx: a relative index under a parent
    //
    // - node_adx: a NUMA domain within a system
    // - pd_adx: a performance domain (CPU frequency domain) within a system
    //   - llc_rdx: an LLC domain (CCX) under a NUMA domain
    //     - core_rdx: a core under a LLC domain
    //       - cpu_rdx: a CPU under a core
    pub node_adx: usize,
    pub pd_adx: usize,
    pub llc_rdx: usize,
    pub core_rdx: usize,
    pub cpu_rdx: usize,
    pub cpu_adx: usize,
    pub smt_level: usize,
    pub cache_size: usize,
    pub cpu_cap: usize,
    pub big_core: bool,
    pub turbo_core: bool,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct ComputeDomainId {
    pub node_adx: usize,
    pub llc_rdx: usize,
    pub is_big: bool,
}

#[derive(Debug, Clone)]
pub struct ComputeDomain {
    pub cpdom_id: usize,
    pub cpdom_alt_id: Cell<usize>,
    pub cpu_ids: Vec<usize>,
    pub neighbor_map: RefCell<BTreeMap<usize, RefCell<Vec<usize>>>>,
}

#[derive(Debug)]
pub struct CpuOrder {
    pub all_cpus_mask: Cpumask,
    pub cpus_pf: Vec<CpuId>,
    pub cpus_ps: Vec<CpuId>,
    pub cpdom_map: BTreeMap<ComputeDomainId, ComputeDomain>,
    pub smt_enabled: bool,
    pub has_biglittle: bool,
}

impl fmt::Display for CpuOrder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for cpu_id in self.cpus_pf.iter() {
            write!(f, "\nCPU in performance: {:?}", cpu_id).ok();
        }
        for cpu_id in self.cpus_ps.iter() {
            write!(f, "\nCPU in powersave: {:?}", cpu_id).ok();
        }
        for (k, v) in self.cpdom_map.iter() {
            write!(f, "\nCPDOM: {:?} {:?}", k, v).ok();
        }
        write!(f, "SMT: {}", self.smt_enabled).ok();
        write!(f, "big/LITTLE: {}", self.has_biglittle).ok();
        Ok(())
    }
}

impl CpuOrder {
    /// Build a cpu preference order
    pub fn new() -> Result<CpuOrder> {
        let ctx = CpuOrderCtx::new();
        let cpus_pf = ctx.build_topo_order(false).unwrap();
        let cpus_ps = ctx.build_topo_order(true).unwrap();
        let cpdom_map = CpuOrderCtx::build_cpdom(&cpus_pf).unwrap();

        if ctx.em.is_ok() {
            let em = &ctx.em.unwrap();
            let emo = EnergyModelOptimizer::new(&ctx.topo, em);
            emo.gen_perf_cpuset_table();
        }

        Ok(CpuOrder {
            all_cpus_mask: ctx.topo.span,
            cpus_pf,
            cpus_ps,
            cpdom_map,
            smt_enabled: ctx.smt_enabled,
            has_biglittle: ctx.has_biglittle,
        })
    }
}

/// CpuOrderCtx is a helper struct used to build a CpuOrder
struct CpuOrderCtx {
    topo: Topology,
    em: Result<EnergyModel>,
    smt_enabled: bool,
    has_biglittle: bool,
}

impl CpuOrderCtx {
    fn new() -> Self {
        let topo = Topology::new().expect("Failed to build host topology");
        let em = EnergyModel::new();
        let smt_enabled = topo.smt_enabled;
        let has_biglittle = topo.has_little_cores();

        debug!("{:#?}", topo);
        debug!("{:#?}", em);

        CpuOrderCtx {
            topo,
            em,
            smt_enabled,
            has_biglittle,
        }
    }

    /// Build a CPU preference order based on its optimization target
    fn build_topo_order(&self, prefer_powersave: bool) -> Option<Vec<CpuId>> {
        let mut cpu_ids = Vec::new();

        // Build a vector of cpu ids.
        for (&node_adx, node) in self.topo.nodes.iter() {
            for (llc_rdx, (&llc_adx, llc)) in node.llcs.iter().enumerate() {
                for (core_rdx, (_core_adx, core)) in llc.cores.iter().enumerate() {
                    for (cpu_rdx, (cpu_adx, cpu)) in core.cpus.iter().enumerate() {
                        let cpu_adx = *cpu_adx;
                        let pd_adx = Self::get_pd_id(&self.em, cpu_adx, llc_adx);
                        let cpu_id = CpuId {
                            node_adx,
                            pd_adx,
                            llc_rdx,
                            core_rdx,
                            cpu_rdx,
                            cpu_adx,
                            smt_level: cpu.smt_level,
                            cache_size: cpu.cache_size,
                            cpu_cap: cpu.cpu_capacity,
                            big_core: cpu.core_type != CoreType::Little,
                            turbo_core: cpu.core_type == CoreType::Big { turbo: true },
                        };
                        cpu_ids.push(RefCell::new(cpu_id));
                    }
                }
            }
        }

        // Convert a vector of RefCell to a vector of plain cpu_ids
        let mut cpu_ids2 = Vec::new();
        for cpu_id in cpu_ids.iter() {
            cpu_ids2.push(cpu_id.borrow().clone());
        }
        let mut cpu_ids = cpu_ids2;

        // Sort the cpu_ids
        match (prefer_powersave, self.has_biglittle) {
            // 1. powersave,      no  big/little
            //     * within the same LLC domain
            //         - node_adx, llc_rdx,
            //     * prefer more capable CPU with higher capacity
            //       and larger cache
            //         - ^cpu_cap (chip binning), ^cache_size,
            //     * prefere the SMT core within the same performance domain
            //         - pd_adx, core_rdx, ^smt_level, cpu_rdx
            (true, false) => {
                cpu_ids.sort_by(|a, b| {
                    a.node_adx
                        .cmp(&b.node_adx)
                        .then_with(|| a.llc_rdx.cmp(&b.llc_rdx))
                        .then_with(|| b.cpu_cap.cmp(&a.cpu_cap))
                        .then_with(|| b.cache_size.cmp(&a.cache_size))
                        .then_with(|| a.pd_adx.cmp(&b.pd_adx))
                        .then_with(|| a.core_rdx.cmp(&b.core_rdx))
                        .then_with(|| b.smt_level.cmp(&a.smt_level))
                        .then_with(|| a.cpu_rdx.cmp(&b.cpu_rdx))
                });
            }
            // 2. powersave,      yes big/little
            //     * within the same LLC domain
            //         - node_adx, llc_rdx,
            //     * prefer energy-efficient LITTLE CPU with a larger cache
            //         - cpu_cap (big/little), ^cache_size,
            //     * prefere the SMT core within the same performance domain
            //         - pd_adx, core_rdx, ^smt_level, cpu_rdx
            (true, true) => {
                cpu_ids.sort_by(|a, b| {
                    a.node_adx
                        .cmp(&b.node_adx)
                        .then_with(|| a.llc_rdx.cmp(&b.llc_rdx))
                        .then_with(|| a.cpu_cap.cmp(&b.cpu_cap))
                        .then_with(|| b.cache_size.cmp(&a.cache_size))
                        .then_with(|| a.pd_adx.cmp(&b.pd_adx))
                        .then_with(|| a.core_rdx.cmp(&b.core_rdx))
                        .then_with(|| b.smt_level.cmp(&a.smt_level))
                        .then_with(|| a.cpu_rdx.cmp(&b.cpu_rdx))
                });
            }
            // 3. performance,    no  big/little
            // 4. performance,    yes big/little
            //     * prefer the non-SMT core
            //         - cpu_rdx,
            //     * fill the same LLC domain first
            //         - node_adx, llc_rdx,
            //     * prefer more capable CPU with higher capacity
            //       (chip binning or big/little) and larger cache
            //         - ^cpu_cap, ^cache_size, smt_level
            //     * within the same power domain
            //         - pd_adx, core_rdx
            _ => {
                cpu_ids.sort_by(|a, b| {
                    a.cpu_rdx
                        .cmp(&b.cpu_rdx)
                        .then_with(|| a.node_adx.cmp(&b.node_adx))
                        .then_with(|| a.llc_rdx.cmp(&b.llc_rdx))
                        .then_with(|| b.cpu_cap.cmp(&a.cpu_cap))
                        .then_with(|| b.cache_size.cmp(&a.cache_size))
                        .then_with(|| a.smt_level.cmp(&b.smt_level))
                        .then_with(|| a.pd_adx.cmp(&b.pd_adx))
                        .then_with(|| a.core_rdx.cmp(&b.core_rdx))
                });
            }
        }

        Some(cpu_ids)
    }

    /// Build a list of compute domains
    fn build_cpdom(cpu_ids: &Vec<CpuId>) -> Option<BTreeMap<ComputeDomainId, ComputeDomain>> {
        // Note that building compute domain is independent to CPU orer
        // so it is okay to use any cpus_*.

        // Creat a compute domain map, where a compute domain is a CPUs that
        // are under the same node and LLC and have the same core type.
        let mut cpdom_id = 0;
        let mut cpdom_map: BTreeMap<ComputeDomainId, ComputeDomain> = BTreeMap::new();
        let mut cpdom_types: BTreeMap<usize, bool> = BTreeMap::new();
        for cpu_id in cpu_ids.iter() {
            let key = ComputeDomainId {
                node_adx: cpu_id.node_adx,
                llc_rdx: cpu_id.llc_rdx,
                is_big: cpu_id.big_core,
            };
            let value = cpdom_map.entry(key.clone()).or_insert_with(|| {
                let val = ComputeDomain {
                    cpdom_id,
                    cpdom_alt_id: Cell::new(cpdom_id),
                    cpu_ids: Vec::new(),
                    neighbor_map: RefCell::new(BTreeMap::new()),
                };
                cpdom_types.insert(cpdom_id, key.is_big);

                cpdom_id += 1;
                val
            });
            value.cpu_ids.push(cpu_id.cpu_adx);
        }

        // Build a neighbor map for each compute domain, where neighbors are
        // ordered by core type, node, and LLC.
        for ((from_k, from_v), (to_k, to_v)) in iproduct!(cpdom_map.iter(), cpdom_map.iter()) {
            if from_k == to_k {
                continue;
            }

            let d = Self::dist(from_k, to_k);
            let mut map = from_v.neighbor_map.borrow_mut();
            match map.get(&d) {
                Some(v) => {
                    v.borrow_mut().push(to_v.cpdom_id);
                }
                None => {
                    map.insert(d, RefCell::new(vec![to_v.cpdom_id]));
                }
            }
        }

        // Fill up cpdom_alt_id for each compute domain.
        for (k, v) in cpdom_map.iter() {
            let mut key = k.clone();
            key.is_big = !k.is_big;

            if let Some(alt_v) = cpdom_map.get(&key) {
                // First, try to find an alternative domain
                // under the same node/LLC.
                v.cpdom_alt_id.set(alt_v.cpdom_id);
            } else {
                // If there is no alternative domain in the same node/LLC,
                // choose the closest one.
                //
                // Note that currently, the idle CPU selection (pick_idle_cpu)
                // is not optimized for this kind of architecture, where big
                // and LITTLE cores are in different node/LLCs.
                'outer: for (_dist, ncpdoms) in v.neighbor_map.borrow().iter() {
                    for ncpdom_id in ncpdoms.borrow().iter() {
                        if let Some(is_big) = cpdom_types.get(ncpdom_id) {
                            if *is_big == key.is_big {
                                v.cpdom_alt_id.set(*ncpdom_id);
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }

        Some(cpdom_map)
    }

    /// Get the performance domain (i.e., CPU frequency domain) ID for a CPU.
    /// If the energy model is not available, use LLC ID instead.
    fn get_pd_id(em: &Result<EnergyModel>, cpu_adx: usize, llc_adx: usize) -> usize {
        match em {
            Ok(em) => em.get_pd_by_cpu_id(cpu_adx).unwrap().id,
            Err(_) => llc_adx,
        }
    }

    /// Calculate distance from two compute domains
    fn dist(from: &ComputeDomainId, to: &ComputeDomainId) -> usize {
        let mut d = 0;
        // core type > numa node > llc
        if from.is_big != to.is_big {
            d += 3;
        }
        if from.node_adx != to.node_adx {
            d += 2;
        } else {
            if from.llc_rdx != to.llc_rdx {
                d += 1;
            }
        }
        d
    }
}

#[derive(Debug)]
struct EnergyModelOptimizer<'a> {
    // CPU topology of a system
    topo: &'a Topology,

    // Energy model of performance domains
    em: &'a EnergyModel,

    // Total performance capacity of the system
    tot_perf: usize,

    // All possible combinations of performance domains & states indexed by performance.
    //     perf: 306 -- power: 116057
    //         pd:id: 0 -- ps:perf: 65 -- ps:power: 19730
    //         pd:id: 0 -- ps:perf: 65 -- ps:power: 19730
    //         pd:id: 1 -- ps:perf: 176 -- ps:power: 76597
    //
    //     perf: 308 -- power: 142649
    //         pd:id: 0 -- ps:perf: 82 -- ps:power: 29049
    //         pd:id: 1 -- ps:perf: 226 -- ps:power: 113600
    pdss_infos: RefCell<BTreeMap<usize, RefCell<HashSet<PDSetInfo<'a>>>>>,

    // Performance domains and states to achieve a certain performance level,
    // which is derived from @pdss_infos.
    perf_pdsi: RefCell<BTreeMap<usize, PDSetInfo<'a>>>,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialOrd)]
struct PDS<'a> {
    pd: &'a PerfDomain,
    ps: &'a PerfState,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialOrd)]
struct PDCpu<'a> {
    pd: &'a PerfDomain,         // performance domain
    cpu_vid: usize,             // virtual ID of a CPU on the performance domain
}

#[derive(Debug, Clone, Eq)]
struct PDSetInfo<'a> {
    performance: usize,
    power: usize,
    pdcpu_set: BTreeSet<PDCpu<'a>>,
    pd_id_set: BTreeSet<usize>,  // pd:id:0, pd:id:1
}

const PD_UNIT: usize       = 100_000_000;
const CPU_UNIT: usize      =     100_000;
const LOOKAHEAD_CNT: usize =          10;

impl<'a> EnergyModelOptimizer<'a> {
    fn new(topo: &'a Topology, em: &'a EnergyModel) -> EnergyModelOptimizer<'a> {
        let tot_perf = em.get_total_performance();

        let pdss_infos: BTreeMap<usize, RefCell<HashSet<PDSetInfo<'a>>>> = BTreeMap::new();
        let pdss_infos = pdss_infos.into();

        let perf_pdsi: BTreeMap<usize, PDSetInfo<'a>> = BTreeMap::new();
        let perf_pdsi = perf_pdsi.into();

        EnergyModelOptimizer { topo, em, tot_perf, pdss_infos, perf_pdsi }
    }

    fn gen_perf_cpuset_table(&'a self) {
        self.gen_all_pds_combinations();
        self.gen_perf_pds_table();
    }

    /// Generate a table of performance vs. performance domain sets
    /// (@self.perf_pdss) from all the possible performance domain & state
    /// combinations (@self.pdss_infos).
    fn gen_perf_pds_table(&'a self) {
        let utils = vec![0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];

        // Find the best performance domains for each system utilization target.
        for &util in utils.iter() {
            let mut best_pdsi: Option<PDSetInfo<'a>> = None;

            match self.perf_pdsi.borrow().last_key_value() {
                Some((_, base)) => {
                    best_pdsi = self.find_perf_pds_for(util, Some(base));
                },
                None => {
                    best_pdsi = self.find_perf_pds_for(util, None);
                },
            };

            if let Some(best_pdsi) = best_pdsi {
                self.perf_pdsi
                    .borrow_mut()
                    .insert(best_pdsi.performance, best_pdsi);
            }
        }

        // Debug print of the generated table
        debug!("## gen_perf_pds_table");
        for (perf, pdsi) in self.perf_pdsi.borrow().iter() {
            debug!("PERF: [_, {}]", perf);
            for pdcpu in pdsi.pdcpu_set.iter() {
                debug!("        pd:id: {:?} -- cpu_vid: {}",
                        pdcpu.pd.id, pdcpu.cpu_vid);
            }
        }
    }

    fn find_perf_pds_for(&'a self, util: f32, base: Option<& PDSetInfo<'a>>) -> Option<PDSetInfo<'a>>{
        let target_perf = (util * self.tot_perf as f32) as usize;
        let mut lookahead = 0;
        let mut min_dist: usize = usize::MAX;
        let mut best_pdsi: Option<PDSetInfo<'a>> = None;

        let pdss_infos = self.pdss_infos.borrow();
        for (&pdsi_perf, pdsi_set) in pdss_infos.iter() {
            if pdsi_perf >= target_perf {
                let pdsi_set_ref = pdsi_set.borrow();
                for pdsi in pdsi_set_ref.iter() {
                    let dist = pdsi.dist(base);
                    if dist < min_dist {
                        min_dist = dist;
                        best_pdsi = Some(pdsi.clone());
                    }
                }
                lookahead += 1;
                if lookahead >= LOOKAHEAD_CNT {
                    break;
                }
            }
        }

        best_pdsi
    }

    /// Generate all possible performance domain & state combinations,
    /// @self.pdss_infos. Each combination represents a set of performance
    /// domains (and their corresponding performance states) that achieve the
    /// requested performance with minimal power consumption.
    ///
    /// The following example demonstrates that to achieve performance level
    /// 306, two CPUs from performance domain 0 and one CPU from performance
    /// domain 1 are required, with a total power consumption of 116057.
    ///
    ///     perf: 306 -- power: 116057
    ///         pd:id: 0 -- ps:perf: 65 -- ps:power: 19730
    ///         pd:id: 0 -- ps:perf: 65 -- ps:power: 19730
    ///         pd:id: 1 -- ps:perf: 176 -- ps:power: 76597
    ///
    ///     perf: 308 -- power: 142649
    ///         pd:id: 0 -- ps:perf: 82 -- ps:power: 29049
    ///         pd:id: 1 -- ps:perf: 226 -- ps:power: 113600
    /// 
    /// We assume a 'reasonable load balancer,' so the CPU utilization of all
    /// the involved CPUs is similar.
    fn gen_all_pds_combinations(&'a self) {
        // Start from the min (0%) and max (100%) CPU utilizations
        let pdsi_vec = self.gen_pds_combinations(0.0);
        self.insert_pds_combinations(&pdsi_vec);

        let pdsi_vec = self.gen_pds_combinations(100.0);
        self.insert_pds_combinations(&pdsi_vec);

        // Then dive into the range between the min and max. 
        self.gen_perf_cpuset_table_range(0, 100);

        // Debug print performance table
        debug!("## gen_all_pds_combinations");
        for (perf, pdss_info) in self.pdss_infos.borrow().iter() {
            debug!("PERF: [_, {}]", perf);
            for pdsi in pdss_info.borrow().iter() {
                debug!("    perf: {} -- power: {}", pdsi.performance, pdsi.power);
                for pdcpu in pdsi.pdcpu_set.iter() {
                    debug!("        pd:id: {:?} -- cpu_vid: {}",
                            pdcpu.pd.id, pdcpu.cpu_vid);
                }
            }
        }
    }

    fn gen_perf_cpuset_table_range(&'a self, low: isize, high: isize) {
        if low > high {
            return;
        }

        // If there is a new performance point in the middle,
        // let's further explore. Otherwise, stop it here.
        let mid: isize = low + (high - low) / 2;
        let pdsi_vec = self.gen_pds_combinations(mid as f32);
        let found_new = self.insert_pds_combinations(&pdsi_vec);
        if found_new {
            self.gen_perf_cpuset_table_range(mid + 1, high);
            self.gen_perf_cpuset_table_range(low, mid - 1);
        }
    }

    fn gen_pds_combinations(&'a self, util: f32) -> Vec<PDSetInfo<'a>> {
        let mut pdsi_vec = Vec::new();

        let pds_set = self.gen_pds_set(util);
        let n = pds_set.len();
        for k in 1..n {
            let pdss = pds_set.clone();
            let pds_cmbs: Vec<_> = Combinations::new(pdss, k)
                                    .map(|cmb| PDSetInfo::new(cmb.clone()))
                                    .collect();
            pdsi_vec.extend(pds_cmbs);
        }

        let pdsi = PDSetInfo::new(pds_set.clone());
        pdsi_vec.push(pdsi);

        pdsi_vec
    }

    fn insert_pds_combinations(&self, new_pdsi_vec: & Vec<PDSetInfo<'a>>) -> bool {
        // For the same performance, keep the PDS combinations with the lowest
        // power consumption. If there are more than one lowest, keep them all
        // to choose one later when assigning CPUs from the selected
        // performance domains.
        let mut found_new = false;

        for new_pdsi in new_pdsi_vec.iter() {
            let mut pdss_infos  = self.pdss_infos.borrow_mut();
            let v = pdss_infos.get(&new_pdsi.performance);
            match v {
                // There are already PDSetInfo in the list.
                Some(v) => {
                    let mut v = v.borrow_mut();
                    let pdsi = &v.iter().next().unwrap();
                    if pdsi.power == new_pdsi.power {
                        // If the power consumptions are the same, keep both.
                        if v.insert(new_pdsi.clone()) {
                            found_new = true;
                        }
                    } else if pdsi.power > new_pdsi.power {
                        // If the new one takes less power, keep the new one.
                        v.clear();
                        v.insert(new_pdsi.clone());
                        found_new = true;
                    }
                },
                // This is the first for the performance target.
                None => {
                    // Let's add it and move on.
                    let mut v: HashSet<PDSetInfo<'a>> = HashSet::new();
                    v.insert(new_pdsi.clone());
                    pdss_infos.insert(new_pdsi.performance, v.into());
                    found_new = true;
                }
            }
        }
        found_new 
    }

    /// Get a vector of (performance domain, performance state) to achieve
    /// the given CPU utilization, @util.
    fn gen_pds_set(&self, util: f32) -> Vec<PDS<'_>> {
        let mut pds_set = vec![];
        for (_, pd) in self.em.perf_doms.iter() {
            let ps = pd.get_ps_by_util(util).unwrap();
            let pds = PDS::new(pd, ps);
            pds_set.push(pds);
        }
        self.expand_pds_set(&mut pds_set);
        pds_set
    }

    /// Expand a PDS vector such that a performance domain with X CPUs
    /// has N elements in the vector. This is purely for generating
    /// combinations easy.
    fn expand_pds_set(&self, pds_set: &mut Vec<PDS<'_>>) {
        let mut xset = vec![];
        // For a performance domain having nr_cpus, add nr_cpus-1 more
        // PDS to make the PDS nr_cpus in the vector.
        for pds in pds_set.iter() {
            let nr_cpus = pds.pd.span.weight();
            for _ in 1..nr_cpus {
                xset.push(pds.clone());
            }
        }
        pds_set.append(&mut xset);

        // Sort the pds_set for easy comparision.
        pds_set.sort();
    }

}

impl<'a> PDS<'_> {
    fn new(pd: &'a PerfDomain, ps: &'a PerfState) -> PDS<'a> {
        PDS { pd, ps }
    }
}

impl PartialEq for PDS<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.pd == other.pd && self.ps == other.ps
    }
}

impl<'a> PDCpu<'_> {
    fn new(pd: &'a PerfDomain, cpu_vid: usize) -> PDCpu<'a> {
        PDCpu { pd, cpu_vid }
    }
}

impl PartialEq for PDCpu<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.pd == other.pd && self.cpu_vid == other.cpu_vid
    }
}

impl fmt::Display for PDS<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "pd:id:{}/pd:weight:{}/ps:cap:{}/ps:power:{}",
            self.pd.id,
            self.pd.span.weight(),
            self.ps.performance,
            self.ps.power,
        )?;
        Ok(())
    }
}

impl<'a> PDSetInfo<'_> {
    fn new(pds_set: Vec<PDS<'a>>) -> PDSetInfo<'a> {
        // Create a pd_id_set and calculate performance and power.
        let mut performance = 0;
        let mut power = 0;
        let mut pd_id_set: BTreeSet<usize> = BTreeSet::new();

        for pds in pds_set.iter() {
            performance += pds.ps.performance;
            power += pds.ps.power;
            pd_id_set.insert(pds.pd.id);
        }

        // Create a pdcpu_set, so first gather the same PDS entires.
        let mut pds_map: BTreeMap<PDS<'a>, RefCell<Vec<PDS<'a>>>> = BTreeMap::new();

        for pds in pds_set.iter() {
            let v = pds_map.get(&pds);
            match v {
                Some(v) => {
                    let mut v = v.borrow_mut();
                    v.push(pds.clone());
                },
                None => {
                    let mut v: Vec<PDS<'a>> = Vec::new();
                    v.push(pds.clone());
                    pds_map.insert(pds.clone(), v.into());
                }
            }
        }
        // Then assign cpu virtual ids to pdcpu_set.
        let mut pdcpu_set: BTreeSet<PDCpu<'a>> = BTreeSet::new();
        let pds_map = pds_map;

        for (_, v) in pds_map.iter() {
            for (cpu_vid, pds) in v.borrow().iter().enumerate() {
                let pdcpu = PDCpu::new(pds.pd, cpu_vid);
                pdcpu_set.insert(pdcpu);
            }
        }

        PDSetInfo{ performance, power, pdcpu_set, pd_id_set }
    }

    /// Calculate the distance from @base to @self. We minimize the number of
    /// performance domains involved to reduce the leakage power consumption.
    /// We then maximize the overlap between the previous (i.e., base)
    /// performance domains and the new one for a smooth transition to the new
    /// cpuset with higher cache locality. Finally, we minimize the number of
    /// CPUs involved, thereby reducing the chance of contention for shared
    /// hardware resources (e.g., shared cache).
    fn dist(&self, base: Option<& PDSetInfo<'a>>) -> usize {
        let nr_pds = self.pd_id_set.len();
        let nr_pds_overlap = match base {
            Some(base) => {
                self.pd_id_set.intersection(&base.pd_id_set).count()
            },
            None => {
                0
            },
        };
        let nr_cpus = self.pdcpu_set.len();

        ((nr_pds - nr_pds_overlap) * PD_UNIT) +         // # non-overlapping PDs
        ((*NR_CPU_IDS - nr_cpus) * CPU_UNIT) +          // # of CPUs
        (*NR_CPU_IDS - self.pd_id_set.first().unwrap()) // PD ID as a tiebreaker
    }
}

impl PartialEq for PDSetInfo<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.performance == other.performance &&
        self.power == other.power &&
        self.pdcpu_set == other.pdcpu_set
    }
}

impl Hash for PDSetInfo<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // We don't need to hash performance, power, and pd_id_set
        // since they are a kind of cache for pds_set.
        self.pdcpu_set.hash(state);
    }
}
