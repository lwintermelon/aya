use core::{marker::PhantomData, mem};

use crate::{
    bindings::{bpf_map_def, bpf_map_type::BPF_MAP_TYPE_RINGBUF},
    helpers::{
        bpf_perf_event_output, bpf_ringbuf_discard, bpf_ringbuf_output, bpf_ringbuf_query,
        bpf_ringbuf_reserve, bpf_ringbuf_submit,
    },
    BpfContext,
};

#[repr(transparent)]
pub struct RingBuf<T> {
    def: bpf_map_def,
    _t: PhantomData<T>,
}

impl<T> RingBuf<T> {
    pub const fn new(max_entries: u32, flags: u32) -> RingBuf<T> {
        RingBuf::with_max_entries(4096 * 64, flags)
    }

    pub const fn with_max_entries(max_entries: u32, flags: u32) -> RingBuf<T> {
        RingBuf {
            def: bpf_map_def {
                type_: BPF_MAP_TYPE_RINGBUF,
                key_size: 0,
                value_size: 0,
                max_entries,
                map_flags: flags,
                id: 0,
                pinning: 0,
            },
            _t: PhantomData,
        }
    }

    pub fn ringbuf_output(&mut self, data: &T, flags: u64) {
        unsafe {
            bpf_ringbuf_output(
                &self.def as *const _ as *mut _,
                data as *const _ as *mut _,
                mem::size_of::<T>() as u64,
                flags,
            );
        }
    }
}
