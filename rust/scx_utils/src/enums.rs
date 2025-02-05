/*
 * WARNING: This file is autogenerated from scripts/gen_enums.py. If you would
 * like to access an enum that is currently missing, add it to the script
 * and run it from the root directory to update this file.
 */

use crate::compat::read_enum;

#[derive(Debug)]
#[allow(non_snake_case)]
pub struct Enums {
    pub SCX_OPS_NAME_LEN: u64,
    pub SCX_SLICE_DFL: u64,
    pub SCX_SLICE_INF: u64,
    pub SCX_DSQ_FLAG_BUILTIN: u64,
    pub SCX_DSQ_FLAG_LOCAL_ON: u64,
    pub SCX_DSQ_INVALID: u64,
    pub SCX_DSQ_GLOBAL: u64,
    pub SCX_DSQ_LOCAL: u64,
    pub SCX_DSQ_LOCAL_ON: u64,
    pub SCX_DSQ_LOCAL_CPU_MASK: u64,
    pub SCX_TASK_QUEUED: u64,
    pub SCX_TASK_RESET_RUNNABLE_AT: u64,
    pub SCX_TASK_DEQD_FOR_SLEEP: u64,
    pub SCX_TASK_STATE_SHIFT: u64,
    pub SCX_TASK_STATE_BITS: u64,
    pub SCX_TASK_STATE_MASK: u64,
    pub SCX_TASK_CURSOR: u64,
    pub SCX_TASK_NONE: u64,
    pub SCX_TASK_INIT: u64,
    pub SCX_TASK_READY: u64,
    pub SCX_TASK_ENABLED: u64,
    pub SCX_TASK_NR_STATES: u64,
    pub SCX_TASK_DSQ_ON_PRIQ: u64,
    pub SCX_KICK_IDLE: u64,
    pub SCX_KICK_PREEMPT: u64,
    pub SCX_KICK_WAIT: u64,
    pub SCX_ENQ_WAKEUP: u64,
    pub SCX_ENQ_HEAD: u64,
    pub SCX_ENQ_CPU_SELECTED: u64,
    pub SCX_ENQ_PREEMPT: u64,
    pub SCX_ENQ_REENQ: u64,
    pub SCX_ENQ_LAST: u64,
    pub SCX_ENQ_CLEAR_OPSS: u64,
    pub SCX_ENQ_DSQ_PRIQ: u64,
}

lazy_static::lazy_static! {
    pub static ref scx_enums: Enums = Enums {
        SCX_OPS_NAME_LEN: read_enum("scx_public_consts","SCX_OPS_NAME_LEN").unwrap(),
        SCX_SLICE_DFL: read_enum("scx_public_consts","SCX_SLICE_DFL").unwrap(),
        SCX_SLICE_INF: read_enum("scx_public_consts","SCX_SLICE_INF").unwrap(),
        SCX_DSQ_FLAG_BUILTIN: read_enum("scx_dsq_id_flags","SCX_DSQ_FLAG_BUILTIN").unwrap(),
        SCX_DSQ_FLAG_LOCAL_ON: read_enum("scx_dsq_id_flags","SCX_DSQ_FLAG_LOCAL_ON").unwrap(),
        SCX_DSQ_INVALID: read_enum("scx_dsq_id_flags","SCX_DSQ_INVALID").unwrap(),
        SCX_DSQ_GLOBAL: read_enum("scx_dsq_id_flags","SCX_DSQ_GLOBAL").unwrap(),
        SCX_DSQ_LOCAL: read_enum("scx_dsq_id_flags","SCX_DSQ_LOCAL").unwrap(),
        SCX_DSQ_LOCAL_ON: read_enum("scx_dsq_id_flags","SCX_DSQ_LOCAL_ON").unwrap(),
        SCX_DSQ_LOCAL_CPU_MASK: read_enum("scx_dsq_id_flags","SCX_DSQ_LOCAL_CPU_MASK").unwrap(),
        SCX_TASK_QUEUED: read_enum("scx_ent_flags","SCX_TASK_QUEUED").unwrap(),
        SCX_TASK_RESET_RUNNABLE_AT: read_enum("scx_ent_flags","SCX_TASK_RESET_RUNNABLE_AT").unwrap(),
        SCX_TASK_DEQD_FOR_SLEEP: read_enum("scx_ent_flags","SCX_TASK_DEQD_FOR_SLEEP").unwrap(),
        SCX_TASK_STATE_SHIFT: read_enum("scx_ent_flags","SCX_TASK_STATE_SHIFT").unwrap(),
        SCX_TASK_STATE_BITS: read_enum("scx_ent_flags","SCX_TASK_STATE_BITS").unwrap(),
        SCX_TASK_STATE_MASK: read_enum("scx_ent_flags","SCX_TASK_STATE_MASK").unwrap(),
        SCX_TASK_CURSOR: read_enum("scx_ent_flags","SCX_TASK_CURSOR").unwrap(),
        SCX_TASK_NONE: read_enum("scx_task_state","SCX_TASK_NONE").unwrap(),
        SCX_TASK_INIT: read_enum("scx_task_state","SCX_TASK_INIT").unwrap(),
        SCX_TASK_READY: read_enum("scx_task_state","SCX_TASK_READY").unwrap(),
        SCX_TASK_ENABLED: read_enum("scx_task_state","SCX_TASK_ENABLED").unwrap(),
        SCX_TASK_NR_STATES: read_enum("scx_task_state","SCX_TASK_NR_STATES").unwrap(),
        SCX_TASK_DSQ_ON_PRIQ: read_enum("scx_ent_dsq_flags","SCX_TASK_DSQ_ON_PRIQ").unwrap(),
        SCX_KICK_IDLE: read_enum("scx_kick_flags","SCX_KICK_IDLE").unwrap(),
        SCX_KICK_PREEMPT: read_enum("scx_kick_flags","SCX_KICK_PREEMPT").unwrap(),
        SCX_KICK_WAIT: read_enum("scx_kick_flags","SCX_KICK_WAIT").unwrap(),
        SCX_ENQ_WAKEUP: read_enum("scx_enq_flags","SCX_ENQ_WAKEUP").unwrap(),
        SCX_ENQ_HEAD: read_enum("scx_enq_flags","SCX_ENQ_HEAD").unwrap(),
        SCX_ENQ_CPU_SELECTED: read_enum("scx_enq_flags","SCX_ENQ_CPU_SELECTED").unwrap(),
        SCX_ENQ_PREEMPT: read_enum("scx_enq_flags","SCX_ENQ_PREEMPT").unwrap(),
        SCX_ENQ_REENQ: read_enum("scx_enq_flags","SCX_ENQ_REENQ").unwrap(),
        SCX_ENQ_LAST: read_enum("scx_enq_flags","SCX_ENQ_LAST").unwrap(),
        SCX_ENQ_CLEAR_OPSS: read_enum("scx_enq_flags","SCX_ENQ_CLEAR_OPSS").unwrap(),
        SCX_ENQ_DSQ_PRIQ: read_enum("scx_enq_flags","SCX_ENQ_DSQ_PRIQ").unwrap(),
    };
}

#[rustfmt::skip]
#[macro_export]
macro_rules! import_enums {
    ($skel: ident) => { 'block : {
        $skel.maps.rodata_data.__SCX_OPS_NAME_LEN = scx_enums.SCX_OPS_NAME_LEN;
        $skel.maps.rodata_data.__SCX_SLICE_DFL = scx_enums.SCX_SLICE_DFL;
        $skel.maps.rodata_data.__SCX_SLICE_INF = scx_enums.SCX_SLICE_INF;
        $skel.maps.rodata_data.__SCX_DSQ_FLAG_BUILTIN = scx_enums.SCX_DSQ_FLAG_BUILTIN;
        $skel.maps.rodata_data.__SCX_DSQ_FLAG_LOCAL_ON = scx_enums.SCX_DSQ_FLAG_LOCAL_ON;
        $skel.maps.rodata_data.__SCX_DSQ_INVALID = scx_enums.SCX_DSQ_INVALID;
        $skel.maps.rodata_data.__SCX_DSQ_GLOBAL = scx_enums.SCX_DSQ_GLOBAL;
        $skel.maps.rodata_data.__SCX_DSQ_LOCAL = scx_enums.SCX_DSQ_LOCAL;
        $skel.maps.rodata_data.__SCX_DSQ_LOCAL_ON = scx_enums.SCX_DSQ_LOCAL_ON;
        $skel.maps.rodata_data.__SCX_DSQ_LOCAL_CPU_MASK = scx_enums.SCX_DSQ_LOCAL_CPU_MASK;
        $skel.maps.rodata_data.__SCX_TASK_QUEUED = scx_enums.SCX_TASK_QUEUED;
        $skel.maps.rodata_data.__SCX_TASK_RESET_RUNNABLE_AT = scx_enums.SCX_TASK_RESET_RUNNABLE_AT;
        $skel.maps.rodata_data.__SCX_TASK_DEQD_FOR_SLEEP = scx_enums.SCX_TASK_DEQD_FOR_SLEEP;
        $skel.maps.rodata_data.__SCX_TASK_STATE_SHIFT = scx_enums.SCX_TASK_STATE_SHIFT;
        $skel.maps.rodata_data.__SCX_TASK_STATE_BITS = scx_enums.SCX_TASK_STATE_BITS;
        $skel.maps.rodata_data.__SCX_TASK_STATE_MASK = scx_enums.SCX_TASK_STATE_MASK;
        $skel.maps.rodata_data.__SCX_TASK_CURSOR = scx_enums.SCX_TASK_CURSOR;
        $skel.maps.rodata_data.__SCX_TASK_NONE = scx_enums.SCX_TASK_NONE;
        $skel.maps.rodata_data.__SCX_TASK_INIT = scx_enums.SCX_TASK_INIT;
        $skel.maps.rodata_data.__SCX_TASK_READY = scx_enums.SCX_TASK_READY;
        $skel.maps.rodata_data.__SCX_TASK_ENABLED = scx_enums.SCX_TASK_ENABLED;
        $skel.maps.rodata_data.__SCX_TASK_NR_STATES = scx_enums.SCX_TASK_NR_STATES;
        $skel.maps.rodata_data.__SCX_TASK_DSQ_ON_PRIQ = scx_enums.SCX_TASK_DSQ_ON_PRIQ;
        $skel.maps.rodata_data.__SCX_KICK_IDLE = scx_enums.SCX_KICK_IDLE;
        $skel.maps.rodata_data.__SCX_KICK_PREEMPT = scx_enums.SCX_KICK_PREEMPT;
        $skel.maps.rodata_data.__SCX_KICK_WAIT = scx_enums.SCX_KICK_WAIT;
        $skel.maps.rodata_data.__SCX_ENQ_WAKEUP = scx_enums.SCX_ENQ_WAKEUP;
        $skel.maps.rodata_data.__SCX_ENQ_HEAD = scx_enums.SCX_ENQ_HEAD;
        $skel.maps.rodata_data.__SCX_ENQ_CPU_SELECTED = scx_enums.SCX_ENQ_CPU_SELECTED;
        $skel.maps.rodata_data.__SCX_ENQ_PREEMPT = scx_enums.SCX_ENQ_PREEMPT;
        $skel.maps.rodata_data.__SCX_ENQ_REENQ = scx_enums.SCX_ENQ_REENQ;
        $skel.maps.rodata_data.__SCX_ENQ_LAST = scx_enums.SCX_ENQ_LAST;
        $skel.maps.rodata_data.__SCX_ENQ_CLEAR_OPSS = scx_enums.SCX_ENQ_CLEAR_OPSS;
        $skel.maps.rodata_data.__SCX_ENQ_DSQ_PRIQ = scx_enums.SCX_ENQ_DSQ_PRIQ;
    }};
}
