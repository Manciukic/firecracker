// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::ops::{Deref, Range};
use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use bitvec::vec::BitVec;
use log::info;
use serde::{Deserialize, Serialize};
use vm_memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryRegion, GuestUsize
};
use vmm_sys_util::eventfd::EventFd;

use super::{MEM_NUM_QUEUES, MEM_QUEUE};
use crate::devices::virtio::block::persist::BlockConstructorArgs;
use crate::devices::virtio::block::virtio::request;
use crate::devices::virtio::mem::request::{BlockRangeState, Request, RequestedRange, Response, ResponseType};
use crate::devices::DeviceError;
use crate::devices::virtio::{block, ActivateError};
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ids::VIRTIO_ID_MEM;
use crate::devices::virtio::generated::virtio_mem::{
    self, virtio_mem_config, virtio_mem_resp_state, VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE, VIRTIO_MEM_STATE_PLUGGED
};
use crate::devices::virtio::iov_deque::IovDequeError;
use crate::devices::virtio::mem::metrics::METRICS;
use crate::devices::virtio::mem::{VIRTIO_MEM_DEV_ID, VIRTIO_MEM_GUEST_ADDRESS};
use crate::devices::virtio::queue::{DescriptorChain, InvalidAvailIdx, Queue, QueueError, FIRECRACKER_MAX_QUEUE_SIZE};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::logger::{IncMetric, debug, error};
use crate::utils::{align_up, bytes_to_mib, mib_to_bytes, u64_to_usize, usize_to_u64};
use crate::vstate::memory::{ByteValued, GuestMemoryMmap, GuestMemorySlot, GuestRegionMmap, GuestRegionType};
use crate::vstate::vm::VmError;
use crate::{Vm, impl_device_type};

// SAFETY: virtio_mem_config only contains plain data types
unsafe impl ByteValued for virtio_mem_config {}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VirtioMemError {
    /// Error while handling an Event file descriptor: {0}
    EventFd(#[from] io::Error),
    /// Received error while sending an interrupt: {0}
    InterruptError(std::io::Error),
    /// Descriptor is write-only
    UnexpectedWriteOnlyDescriptor,
    /// Error reading virtio descriptor
    DescriptorWriteFailed,
    /// Error writing virtio descriptor
    DescriptorReadFailed,
    /// Unknown request type: {0:?}
    UnknownRequestType(u32),
    /// Descriptor chain is too short
    DescriptorChainTooShort,
    /// Descriptor is too small
    DescriptorLengthTooSmall,
    /// Descriptor is read-only
    UnexpectedReadOnlyDescriptor,
    /// Error popping from virtio queue: {0}
    InvalidAvailIdx(#[from] InvalidAvailIdx),
    /// Size {0} is invalid: it must be a multiple of block size and less than the total size
    InvalidSize(u64),
    /// Device is not active
    DeviceNotActive,
    /// Invalid requested range: {0:?}.
    InvalidRange(RequestedRange),
    /// The requested range cannot be {0:?} because it's {1:?}.
    BlockStateInvalid(&'static str, BlockRangeState),
    /// Error adding used queue: {0}
    QueueError(#[from] QueueError),
    /// Error discarding the memory range: {0}
    DiscardRangeError(std::io::Error),
    /// Error plugging/unplugging a memory slot: {0}
    PlugSlotError(VmError),
}

#[derive(Debug)]
pub struct VirtioMem {
    // VirtIO fields
    avail_features: u64,
    acked_features: u64,
    activate_event: EventFd,

    // Transport fields
    device_state: DeviceState,
    pub(crate) queues: Vec<Queue>,
    queue_events: Vec<EventFd>,

    // Device specific fields
    pub(crate) config: virtio_mem_config,
    pub(crate) slot_size: usize,
    // Bitmap to track which blocks are plugged (1 bit per 2MB block)
    pub(crate) plugged_blocks: BitVec,
    vm: Arc<Vm>,
}

/// Memory hotplug device status information.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VirtioMemStatus {
    /// Block size in MiB.
    pub block_size_mib: usize,
    /// Total memory size in MiB that can be hotplugged.
    pub total_size_mib: usize,
    /// Size of the KVM slots in MiB.
    pub slot_size_mib: usize,
    /// Currently plugged memory size in MiB.
    pub plugged_size_mib: usize,
    /// Requested memory size in MiB.
    pub requested_size_mib: usize,
}

impl VirtioMem {
    pub fn new(
        vm: Arc<Vm>,
        total_size_mib: usize,
        block_size_mib: usize,
        slot_size_mib: usize,
    ) -> Result<Self, VirtioMemError> {
        let queues = vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); MEM_NUM_QUEUES];
        let config = virtio_mem_config {
            addr: VIRTIO_MEM_GUEST_ADDRESS.raw_value(),
            region_size: mib_to_bytes(total_size_mib) as u64,
            block_size: mib_to_bytes(block_size_mib) as u64,
            ..Default::default()
        };
        let plugged_blocks = BitVec::repeat(false, total_size_mib/block_size_mib);

        Self::from_state(vm, queues, config, mib_to_bytes(slot_size_mib), plugged_blocks)
    }

    pub fn from_state(
        vm: Arc<Vm>,
        queues: Vec<Queue>,
        config: virtio_mem_config,
        slot_size: usize,
        plugged_blocks: BitVec,
    ) -> Result<Self, VirtioMemError> {
        let activate_event = EventFd::new(libc::EFD_NONBLOCK)?;
        let queue_events = (0..MEM_NUM_QUEUES)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK))
            .collect::<Result<Vec<EventFd>, io::Error>>()?;

        Ok(Self {
            avail_features: (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE),
            acked_features: 0u64,
            activate_event,
            device_state: DeviceState::Inactive,
            queues,
            queue_events,
            config,
            vm,
            slot_size,
            plugged_blocks,
        })
    }

    pub fn id(&self) -> &str {
        VIRTIO_MEM_DEV_ID
    }

    /// Gets the total hotpluggable size.
    pub fn total_size_mib(&self) -> usize {
        bytes_to_mib(u64_to_usize(self.config.region_size))
    }

    /// Gets the block size.
    pub fn block_size_mib(&self) -> usize {
        bytes_to_mib(u64_to_usize(self.config.block_size))
    }

    /// Gets the block size.
    pub fn slot_size_mib(&self) -> usize {
        bytes_to_mib(self.slot_size)
    }

    /// Gets the total size of the plugged memory blocks.
    pub fn plugged_size_mib(&self) -> usize {
        bytes_to_mib(u64_to_usize(self.config.plugged_size))
    }

    /// Gets the requested size
    pub fn requested_size_mib(&self) -> usize {
        bytes_to_mib(u64_to_usize(self.config.requested_size))
    }

    pub fn status(&self) -> VirtioMemStatus {
        VirtioMemStatus {
            block_size_mib: self.block_size_mib(),
            total_size_mib: self.total_size_mib(),
            slot_size_mib: self.slot_size_mib(),
            plugged_size_mib: self.plugged_size_mib(),
            requested_size_mib: self.requested_size_mib(),
        }
    }

    fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.device_state.active_state().unwrap().mem
    }

    fn signal_used_queue(&self) -> Result<(), VirtioMemError> {
        self.interrupt_trigger()
            .trigger(VirtioInterruptType::Queue(MEM_QUEUE.try_into().unwrap()))
            .map_err(VirtioMemError::InterruptError)
    }

    fn is_range_plugged(&self, range: &RequestedRange) -> Result<BlockRangeState, VirtioMemError> {
        let plugged_count = self.plugged_blocks[self.checked_block_range(range)?].count_ones();

        Ok(match plugged_count {
            nb_blocks if nb_blocks == range.nb_blocks => BlockRangeState::Plugged,
            0 => BlockRangeState::Unplugged,
            _ => BlockRangeState::Mixed,
        })
    }

    fn parse_request(
        &self,
        avail_desc: &DescriptorChain,
    ) -> Result<(Request, GuestAddress, u16), VirtioMemError> {
        // The head contains the request type which MUST be readable.
        if avail_desc.is_write_only() {
            return Err(VirtioMemError::UnexpectedWriteOnlyDescriptor);
        }
        
        if (avail_desc.len as usize) < size_of::<virtio_mem::virtio_mem_req>() {
            return Err(VirtioMemError::DescriptorLengthTooSmall);
        }

        let request: virtio_mem::virtio_mem_req = self.guest_memory().read_obj(avail_desc.addr)
            .map_err(|_| VirtioMemError::DescriptorReadFailed)?;

        let resp_desc = avail_desc
            .next_descriptor()
            .ok_or(VirtioMemError::DescriptorChainTooShort)?;

        // The response MUST always be writable.
        if !resp_desc.is_write_only() {
            return Err(VirtioMemError::UnexpectedReadOnlyDescriptor);
        }

        if (resp_desc.len as usize) < std::mem::size_of::<virtio_mem::virtio_mem_resp>() {
            return Err(VirtioMemError::DescriptorLengthTooSmall);
        }

        Ok((request.into(), resp_desc.addr, resp_desc.index))
    }

    fn write_response(&mut self, resp: Response, resp_addr: GuestAddress, resp_index: u16) -> Result<(), VirtioMemError> {
        self.guest_memory()
            .write_obj(virtio_mem::virtio_mem_resp::from(resp), resp_addr)
            .map_err(|_| VirtioMemError::DescriptorWriteFailed)
            .map(|_| size_of::<virtio_mem::virtio_mem_resp>())?;
        self.queues[MEM_QUEUE].add_used(resp_index, u32::try_from(std::mem::size_of::<virtio_mem::virtio_mem_resp>()).unwrap()).map_err(VirtioMemError::QueueError)
    }

    fn checked_block_range(&self, range: &RequestedRange) -> Result<Range<usize>, VirtioMemError> {
        if range.addr.0 % self.config.block_size != 0 {
            return Err(VirtioMemError::InvalidRange(*range))
        }

        let start_offset = range.addr.checked_offset_from(GuestAddress(self.config.addr)).ok_or(VirtioMemError::InvalidRange(*range))?;
        let start_block = start_offset.checked_div(self.config.block_size).map(u64_to_usize).ok_or(VirtioMemError::InvalidRange(*range))?;
        let end_block_excl = start_block + range.nb_blocks;
        
        if end_block_excl > self.plugged_blocks.len() {
            return Err(VirtioMemError::InvalidRange(*range))
        }

        Ok(start_block..end_block_excl)
    }

    fn validate_range(&self, range: &RequestedRange) -> Result<(), VirtioMemError> {
        let end_addr = range.addr.checked_add(usize_to_u64(range.nb_blocks) * self.config.block_size).ok_or(VirtioMemError::InvalidRange(*range))?;
        if range.addr.0 < self.config.addr || end_addr.0 > self.config.addr + self.config.region_size {
            return Err(VirtioMemError::InvalidRange(*range));
        }
        Ok(())
    }

    fn handle_plug_request(&mut self, range: &RequestedRange, resp_addr: GuestAddress, resp_idx: u16) -> Result<(), VirtioMemError> {
        METRICS.plug_count.inc();
        let _metric = METRICS.plug_agg.record_latency_metrics();
        let response = self.is_range_plugged(range).and_then(|state| match state {
            BlockRangeState::Unplugged => self.plug_range(range, true),
            state => Err(VirtioMemError::BlockStateInvalid("plugged", state))
        }).map_or_else(|err| {
            METRICS.plug_fail.inc();
            error!("virtio-mem: Failed to plug range: {}", err);
            Response::error()
        }, 
        |_| Response::ack()
        );
        self.write_response(response, resp_addr, resp_idx)
    }

    fn handle_unplug_request(&mut self, range: &RequestedRange, resp_addr: GuestAddress, resp_idx: u16) -> Result<(), VirtioMemError> {
        METRICS.unplug_count.inc();
        let _metric = METRICS.unplug_agg.record_latency_metrics();
        let response = self.is_range_plugged(range).and_then(|state| match state {
            BlockRangeState::Plugged => self.plug_range(range, false),
            state => Err(VirtioMemError::BlockStateInvalid("unplugged", state))
        }).map_or_else(|err| {
            METRICS.unplug_fail.inc();
            error!("virtio-mem: Failed to unplug range: {}", err);
            Response::error()
        }, 
        |_| Response::ack()
        );
        self.write_response(response, resp_addr, resp_idx)
    }

    fn handle_unplug_all_request(&mut self, resp_addr: GuestAddress, resp_idx: u16) -> Result<(), VirtioMemError> {
        METRICS.unplug_all_count.inc();
        let _metric = METRICS.unplug_all_agg.record_latency_metrics();
        let range = RequestedRange {
            addr: GuestAddress(self.config.addr),
            nb_blocks: self.plugged_blocks.len(),
        };
        self.plug_range(&range, false);
        let response = self.plug_range(&range, false).map_or_else(|err| {
            METRICS.unplug_all_fail.inc();
            error!("virtio-mem: Failed to unplug all: {}", err);
            Response::error()
        }, 
        |_| Response::ack()
        );
        self.write_response(response, resp_addr, resp_idx)
    }

    fn handle_state_request(&mut self, range: &RequestedRange, resp_addr: GuestAddress, resp_idx: u16) -> Result<(), VirtioMemError> {
        METRICS.state_count.inc();
        let _metric = METRICS.state_agg.record_latency_metrics();
        let response = self.is_range_plugged(range).map_or_else(|err| {
            METRICS.state_fail.inc();
            error!("virtio-mem: Failed to retrieve state of range: {}", err);
            Response::error()
        }, 
        Response::ack_with_state
        );
        self.write_response(response, resp_addr, resp_idx)
    }

    fn process_mem_queue(&mut self) -> Result<(), VirtioMemError> {
        while let Some(desc) = self.queues[MEM_QUEUE].pop()? {
            METRICS.queue_event_count.inc();

            let index = desc.index;

            let (req, resp_addr, resp_idx) = self.parse_request(&desc)?;
            debug!("virtio-mem: Request: {:?}", req);
            // Handle request and write response
            match req {
                Request::State(ref range) => self.handle_state_request(range, resp_addr, resp_idx),
                Request::Plug(ref range) => self.handle_plug_request(range, resp_addr, resp_idx),
                Request::Unplug(ref range) => self.handle_unplug_request(range, resp_addr, resp_idx),
                Request::UnplugAll => self.handle_unplug_all_request(resp_addr, resp_idx),
                Request::Unsupported(t) => {
                    Err(VirtioMemError::UnknownRequestType(t))
                }
            }?;
        }

        self.queues[MEM_QUEUE].advance_used_ring_idx();
        self.signal_used_queue()?;

        Ok(())
    }

    pub(crate) fn process_mem_queue_event(&mut self) {
        if let Err(err) = self.queue_events[MEM_QUEUE].read() {
            error!("Failed to read mem queue event: {err}");
            METRICS.queue_event_fails.inc();
            return;
        }

        if let Err(err) = self.process_mem_queue() {
            error!("virtio-mem: Failed to process queue: {err}");
            METRICS.queue_event_fails.inc();
        }
    }

    pub fn process_virtio_queues(&mut self) -> Result<(), VirtioMemError> {
        self.process_mem_queue()
    }

    pub(crate) fn set_avail_features(&mut self, features: u64) {
        self.avail_features = features;
    }

    pub(crate) fn set_acked_features(&mut self, features: u64) {
        self.acked_features = features;
    }

    pub(crate) fn activate_event(&self) -> &EventFd {
        &self.activate_event
    }

    fn update_kvm_slots(
        &self,
    ) -> Result<(), VirtioMemError> {
        let hp_region = self.guest_memory().iter().find(|r| r.region_type() == GuestRegionType::Hotpluggable).unwrap();
        hp_region.all_slots().try_for_each(|slot| {
            let range = RequestedRange {
                addr: slot.guest_addr,
                nb_blocks: slot.size.checked_div(u64_to_usize(self.config.block_size)).expect("slot size should be a multiple of block size"),
            };
            let plugged_blocks_slice = &self.plugged_blocks[self.checked_block_range(&range).expect("slot should be within hotpluggable range")];
            // internally SlottedGuestMemoryRegion checks whether it's already plugged/unplugged
            if plugged_blocks_slice.any() {
                hp_region.plug_unplug_slot(&self.vm, slot.slot, true)
            } else if plugged_blocks_slice.not_any() {
                hp_region.plug_unplug_slot(&self.vm, slot.slot, false)
            } else {
                Ok(())
            }.map_err(VirtioMemError::PlugSlotError)
        })
    }

    // TODO use common function with BalloonDevice
    fn discard_range(&self, range: &RequestedRange) -> Result<(), VirtioMemError> {
        let size = range.nb_blocks * u64_to_usize(self.config.block_size);
        let gpa = range.addr;
        let hva = self
            .guest_memory()
            .get_host_address(gpa)
            .unwrap();

        // TODO handle file-backed devices
        // SAFETY: valid parameters
        let ret = unsafe {
            libc::madvise(hva.cast(), size, libc::MADV_DONTNEED)
        };
        if ret < 0 {
            return Err(VirtioMemError::DiscardRangeError(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn plug_range(
        &mut self,
        range: &RequestedRange,
        plug: bool,
    ) -> Result<(), VirtioMemError> {
        // Update internal representation
        let block_range = self.checked_block_range(range)?;
        let plugged_blocks_slice = &mut self.plugged_blocks[block_range];
        let plugged_before = usize_to_u64(plugged_blocks_slice.count_ones());
        plugged_blocks_slice.fill(plug);
        let plugged_after = usize_to_u64(plugged_blocks_slice.count_ones());
        self.config.plugged_size -= (plugged_before * self.config.block_size);
        self.config.plugged_size += (plugged_after * self.config.block_size);

        // If unplugging, discard the range
        if !plug {
            self.discard_range(range)?;
        }

        // scan KVM slots to see if they can be plugged/unplugged
        self.update_kvm_slots();

        Ok(())
    }

    /// Updates the requested size of the virtio-mem device.
    pub fn update_requested_size(
        &mut self,
        requested_size: u64,
        vm: &Vm,
    ) -> Result<(), VirtioMemError> {
        if !self.is_activated() {
            return Err(VirtioMemError::DeviceNotActive);
        }

        if requested_size % self.config.block_size != 0 {
            return Err(VirtioMemError::InvalidSize(requested_size));
        }
        if requested_size > self.config.region_size {
            return Err(VirtioMemError::InvalidSize(requested_size));
        }

        if self.config.usable_region_size < requested_size {
            self.config.usable_region_size = requested_size.next_multiple_of(usize_to_u64(self.slot_size));
            debug!(
                "virtio-mem: Updated usable size to {} bytes",
                self.config.usable_region_size
            );
        }

        self.config.requested_size = requested_size;
        debug!(
            "virtio-mem: Updated requested size to {} bytes",
            requested_size
        );
        self.interrupt_trigger()
            .trigger(VirtioInterruptType::Config)
            .map_err(VirtioMemError::InterruptError)
    }
}

impl VirtioDevice for VirtioMem {
    impl_device_type!(VIRTIO_ID_MEM);

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not activated")
            .interrupt
            .deref()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let offset = u64_to_usize(offset);
        self.config
            .as_slice()
            .get(offset..offset + data.len())
            .map(|s| data.copy_from_slice(s))
            .unwrap_or_else(|| {
                error!(
                    "virtio-mem: Config read offset+length {offset}+{} out of bounds",
                    data.len()
                )
            })
    }

    fn write_config(&mut self, offset: u64, _data: &[u8]) {
        error!("virtio-mem: Attempted write to read-only config space at offset {offset}");
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        if (self.acked_features & (1 << VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE)) == 0 {
            error!(
                "virtio-mem: VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE feature not acknowledged by guest"
            );
            METRICS.activate_fails.inc();
            return Err(ActivateError::RequiredFeatureNotAcked(
                "VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE",
            ));
        }

        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        if self.activate_event.write(1).is_err() {
            METRICS.activate_fails.inc();
            self.device_state = DeviceState::Inactive;
            return Err(ActivateError::EventFd);
        }

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use crate::vstate::vm::tests::setup_vm_with_memory;

    pub(crate) fn default_virtio_mem() -> VirtioMem {
        let (_, vm) = setup_vm_with_memory(0x1000);
        let vm = Arc::new(vm);
        VirtioMem::new(vm, 1024, 2, 128).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use vm_memory::mmap::MmapRegionBuilder;

    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::mem::device::test_utils::default_virtio_mem;
    use crate::vstate::vm::tests::setup_vm_with_memory;

    #[test]
    fn test_new() {
        let mem = default_virtio_mem();

        assert_eq!(mem.total_size_mib(), 1024);
        assert_eq!(mem.block_size_mib(), 2);
        assert_eq!(mem.plugged_size_mib(), 0);
        assert_eq!(mem.id(), VIRTIO_MEM_DEV_ID);
        assert_eq!(mem.device_type(), VIRTIO_ID_MEM);

        let features = (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE);
        assert_eq!(mem.avail_features(), features);
        assert_eq!(mem.acked_features(), 0);

        assert!(!mem.is_activated());

        assert_eq!(mem.queues().len(), MEM_NUM_QUEUES);
        assert_eq!(mem.queue_events().len(), MEM_NUM_QUEUES);
    }

    #[test]
    fn test_from_state() {
        let (_, vm) = setup_vm_with_memory(0x1000);
        let vm = Arc::new(vm);
        let queues = vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); MEM_NUM_QUEUES];
        let region_size_mib = 2048;
        let block_size_mib = 2;
        let slot_size_mib = 128;
        let plugged_size_mib = 512;
        let usable_region_size = mib_to_bytes(1024) as u64;
        let config = virtio_mem_config {
            addr: VIRTIO_MEM_GUEST_ADDRESS.raw_value(),
            region_size: mib_to_bytes(region_size_mib) as u64,
            block_size: mib_to_bytes(block_size_mib) as u64,
            plugged_size: mib_to_bytes(plugged_size_mib) as u64,
            usable_region_size,
            ..Default::default()
        };
        let plugged_blocks = BitVec::repeat(false, mib_to_bytes(region_size_mib) / mib_to_bytes(block_size_mib));
        let mem = VirtioMem::from_state(vm, queues, config, mib_to_bytes(slot_size_mib), plugged_blocks).unwrap();
        assert_eq!(mem.total_size_mib(), region_size_mib);
        assert_eq!(mem.block_size_mib(), block_size_mib);
        assert_eq!(mem.slot_size_mib(), slot_size_mib);
        assert_eq!(mem.plugged_size_mib(), plugged_size_mib);
        assert_eq!(mem.config.usable_region_size, usable_region_size);
    }

    #[test]
    fn test_read_config() {
        let mem = default_virtio_mem();
        let mut data = [0u8; 8];

        mem.read_config(0, &mut data);
        assert_eq!(
            u64::from_le_bytes(data),
            mib_to_bytes(mem.block_size_mib()) as u64
        );

        mem.read_config(16, &mut data);
        assert_eq!(
            u64::from_le_bytes(data),
            VIRTIO_MEM_GUEST_ADDRESS.raw_value()
        );

        mem.read_config(24, &mut data);
        assert_eq!(
            u64::from_le_bytes(data),
            mib_to_bytes(mem.total_size_mib()) as u64
        );
    }

    #[test]
    fn test_read_config_out_of_bounds() {
        let mem = default_virtio_mem();

        let mut data = [0u8; 8];
        let config_size = std::mem::size_of::<virtio_mem_config>();
        mem.read_config(config_size as u64, &mut data);
        assert_eq!(data, [0u8; 8]); // Should remain unchanged

        let mut data = vec![0u8; config_size];
        mem.read_config(8, &mut data);
        assert_eq!(data, vec![0u8; config_size]); // Should remain unchanged
    }

    #[test]
    fn test_write_config() {
        let mut mem = default_virtio_mem();
        let data = [1u8; 8];
        mem.write_config(0, &data); // Should log error but not crash

        // should not change config
        let mut data = [0u8; 8];
        mem.read_config(0, &mut data);
        let block_size = u64::from_le_bytes(data);
        assert_eq!(block_size, mib_to_bytes(2) as u64);
    }

    #[test]
    fn test_set_features() {
        let mut mem = default_virtio_mem();
        mem.set_avail_features(123);
        assert_eq!(mem.avail_features(), 123);
        mem.set_acked_features(456);
        assert_eq!(mem.acked_features(), 456);
    }

    #[test]
    fn test_status() {
        let mut mem = default_virtio_mem();
        let status = mem.status();
        assert_eq!(
            status,
            VirtioMemStatus {
                block_size_mib: 2,
                total_size_mib: 1024,
                slot_size_mib: 128,
                plugged_size_mib: 0,
                requested_size_mib: 0,
            }
        );
    }
}
