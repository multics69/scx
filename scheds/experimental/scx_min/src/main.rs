// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Changwoo Min <changwoo@igalia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! A simple sched_ext scheduler.
//!
//! See the top-level comment in src/bpf/main.bpf.c for more details.

mod bpf_skel;
pub use bpf_skel::*;

use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::OpenObject;
use log::info;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

const SCHEDULER_NAME: &str = "scx_min";

/// A simple sched_ext scheduler.
///
/// By default, it operates as a simple global weighted vtime scheduler and can
/// be switched to FIFO scheduling.
#[derive(Debug, Parser)]
struct Opts {
    /// Use FIFO scheduling instead of weighted vtime scheduling.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    fifo: bool,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        try_set_rlimit_infinity();

        info!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, min_ops, open_opts)?;
        skel.struct_ops.min_ops_mut().exit_dump_len = opts.exit_dump_len;

        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.fifo_sched = opts.fifo;

        let mut skel = scx_ops_load!(skel, min_ops, uei)?;
        let struct_ops = Some(scx_ops_attach!(skel, min_ops)?);

        Ok(Self { skel, struct_ops })
    }

    /// Sum the per-CPU [local, global] queueing counters.
    fn read_stats(&self) -> Result<[u64; 2]> {
        let mut stats = [0u64; 2];

        for (idx, stat) in stats.iter_mut().enumerate() {
            let cpu_vals = self
                .skel
                .maps
                .stats
                .lookup_percpu(&(idx as u32).to_ne_bytes(), MapFlags::ANY)
                .with_context(|| format!("Failed to lookup stat {idx}"))?
                .unwrap_or_default();
            *stat = cpu_vals
                .iter()
                .map(|val| u64::from_ne_bytes(val.as_slice().try_into().unwrap()))
                .sum();
        }

        Ok(stats)
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            let [local, global] = self.read_stats()?;
            println!("local={local} global={global}");
            std::thread::sleep(Duration::from_secs(1));
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    let loglevel = simplelog::LevelFilter::Info;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
