// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fs::File;
use std::io::SeekFrom;
use std::sync::{Arc, Mutex};

use bitvec::vec::BitVec;
use kvm_bindings::{KVM_MEM_LOG_DIRTY_PAGES, kvm_userspace_memory_region};
use serde::{Deserialize, Serialize};
pub use vm_memory::bitmap::{AtomicBitmap, BS, Bitmap, BitmapSlice};
pub use vm_memory::mmap::MmapRegionBuilder;
use vm_memory::mmap::{MmapRegionError, NewBitmap};
pub use vm_memory::{
    Address, ByteValued, Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryRegion,
    GuestUsize, MemoryRegionAddress, MmapRegion, address,
};
use vm_memory::{Error as VmMemoryError, GuestMemoryError, VolatileSlice, WriteVolatile};
use vmm_sys_util::errno;

use crate::utils::{get_page_size, u64_to_usize};
use crate::vmm_config::machine_config::HugePageConfig;
use crate::vstate::vm::VmError;
use crate::{DirtyBitmap, Vm};

/// Type of GuestMemoryMmap.
pub type GuestMemoryMmap =
    crate::vm_memory_vendored::GuestRegionCollection<SlottedGuestMemoryRegion>;
/// Type of GuestRegionMmap.
pub type GuestRegionMmap = vm_memory::GuestRegionMmap<Option<AtomicBitmap>>;
/// Type of GuestMmapRegion.
pub type GuestMmapRegion = vm_memory::MmapRegion<Option<AtomicBitmap>>;

/// Errors associated with dumping guest memory to file.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MemoryError {
    /// Cannot fetch system's page size: {0}
    PageSize(errno::Error),
    /// Cannot dump memory: {0}
    WriteMemory(GuestMemoryError),
    /// Cannot create mmap region: {0}
    MmapRegionError(MmapRegionError),
    /// Cannot create guest memory: {0}
    VmMemoryError(VmMemoryError),
    /// Cannot create memfd: {0}
    Memfd(memfd::Error),
    /// Cannot resize memfd file: {0}
    MemfdSetLen(std::io::Error),
    /// Total sum of memory regions exceeds largest possible file offset
    OffsetTooLarge,
    /// Memory region is not aligned
    Unaligned,
    /// Memory slot is invalid: {0}
    InvalidSlot(u32),
}

/// Type of the guest region
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GuestRegionType {
    /// Guest DRAM
    Dram,
    /// Hotpluggable memory via virtio-mem
    Hotpluggable,
}

/// A memory region which is slotted into multiple kvm userspace memory regions
/// which can be plugged or unplugged at any time.
#[derive(Debug)]
pub struct SlottedGuestMemoryRegion {
    region: GuestRegionMmap,
    region_type: GuestRegionType,
    slot_from: u32,
    slot_size: usize,
    plugged: Mutex<BitVec>,
}

/// A snapshot of the state of a memory slot
#[derive(Debug)]
pub struct GuestMemorySlot {
    /// KVM memory slot number
    pub(crate) slot: u32,
    /// Start guest address of the slot
    pub(crate) guest_addr: GuestAddress,
    /// Corresponding host address
    pub(crate) host_addr: *mut u8,
    /// Size of the slot in bytes
    pub(crate) size: usize,
    /// Offset of the slot relative to the region
    pub(crate) offset: usize,
    /// KVM userspace memory region flags
    pub(crate) flags: u32,
}

impl From<GuestMemorySlot> for kvm_userspace_memory_region {
    fn from(mem_slot: GuestMemorySlot) -> Self {
        kvm_userspace_memory_region {
            flags: mem_slot.flags,
            slot: mem_slot.slot,
            guest_phys_addr: mem_slot.guest_addr.raw_value(),
            memory_size: mem_slot.size as u64,
            userspace_addr: mem_slot.host_addr as u64,
        }
    }
}

fn addr_in_range(addr: GuestAddress, start: GuestAddress, len: usize) -> bool {
    if let Some(end) = start.checked_add(len as u64) {
        addr >= start && addr < end
    } else {
        false
    }
}

#[allow(dead_code)]
impl SlottedGuestMemoryRegion {
    pub(crate) fn dram_from_mmap_region(region: GuestRegionMmap, slot: u32) -> Self {
        let slot_size = u64_to_usize(region.len());
        SlottedGuestMemoryRegion {
            region,
            region_type: GuestRegionType::Dram,
            slot_from: slot,
            slot_size,
            plugged: Mutex::new(BitVec::repeat(true, 1)),
        }
    }

    pub(crate) fn hotpluggable_from_mmap_region(
        region: GuestRegionMmap,
        slot_from: u32,
        slot_size: usize,
    ) -> Result<Self, MemoryError> {
        let slot_cnt = u64_to_usize(region.len())
            .checked_div(slot_size)
            .ok_or(MemoryError::Unaligned)?;

        Ok(SlottedGuestMemoryRegion {
            region,
            region_type: GuestRegionType::Dram,
            slot_from,
            slot_size,
            // TODO(virtio-mem): we will unplug it by default in the future
            plugged: Mutex::new(BitVec::repeat(true, slot_cnt)),
        })
    }

    pub(crate) fn from_state(
        region: GuestRegionMmap,
        state: &GuestMemoryRegionState,
        slot: u32,
    ) -> Result<Self, MemoryError> {
        let slot_cnt = state.plugged.len();
        let slot_size = u64_to_usize(region.len())
            .checked_div(slot_cnt)
            .ok_or(MemoryError::Unaligned)?;

        Ok(SlottedGuestMemoryRegion {
            region,
            slot_size,
            region_type: state.region_type,
            slot_from: slot,
            plugged: Mutex::new(state.plugged.clone()),
        })
    }

    pub(crate) fn inner(&self) -> &GuestRegionMmap {
        &self.region
    }

    pub(crate) fn region_type(&self) -> GuestRegionType {
        self.region_type
    }

    pub(crate) fn slot_cnt(&self) -> u32 {
        u32::try_from(u64_to_usize(self.region.len()) / self.slot_size).unwrap()
    }

    pub(crate) fn mem_slot(&self, slot: u32) -> Option<GuestMemorySlot> {
        if slot < self.slot_from || slot >= self.slot_from + self.slot_cnt() {
            None
        } else {
            let offset = ((slot - self.slot_from) as usize) * self.slot_size;
            let flags = if self.region.bitmap().is_some() {
                KVM_MEM_LOG_DIRTY_PAGES
            } else {
                0
            };
            Some(GuestMemorySlot {
                slot,
                offset,
                flags,
                size: self.slot_size,
                guest_addr: self.region.start_addr().checked_add(offset as u64)?,
                host_addr: self.region.as_ptr().wrapping_add(offset),
            })
        }
    }

    pub(crate) fn all_slots(&self) -> impl Iterator<Item = GuestMemorySlot> {
        (0..self.slot_cnt()).map(|i| self.mem_slot(self.slot_from + i).unwrap())
    }

    pub(crate) fn plugged_slots(&self) -> impl Iterator<Item = GuestMemorySlot> {
        let bitmap_guard = self.plugged.lock().unwrap();
        self.all_slots()
            .filter(|mem_slot| {
                bitmap_guard
                    .get((mem_slot.slot - self.slot_from) as usize)
                    .is_some_and(|b| *b)
            })
            .collect::<Vec<_>>()
            .into_iter()
    }

    pub(crate) fn slots_inside_range(
        &self,
        from: GuestAddress,
        len: usize,
    ) -> impl Iterator<Item = GuestMemorySlot> {
        self.all_slots().filter(move |slot| {
            if let Some(to) = from.checked_add(len as u64) {
                addr_in_range(from, slot.guest_addr, slot.size)
                    && addr_in_range(to, slot.guest_addr, slot.size)
            } else {
                false
            }
        })
    }

    pub(crate) fn slots_intersecting_range(
        &self,
        from: GuestAddress,
        len: usize,
    ) -> impl Iterator<Item = GuestMemorySlot> {
        self.all_slots().filter(move |slot| {
            if let Some(slot_end) = slot.guest_addr.checked_add(slot.size as u64) {
                addr_in_range(slot.guest_addr, from, len) || addr_in_range(slot_end, from, len)
            } else {
                false
            }
        })
    }

    pub(crate) fn plug_unplug_slot(&self, vm: &Vm, slot: u32, plug: bool) -> Result<(), VmError> {
        let mem_slot = self.mem_slot(slot).ok_or(MemoryError::InvalidSlot(slot))?;
        let mut bitmap_guard = self.plugged.lock().unwrap();
        let prev = bitmap_guard.replace((slot - self.slot_from) as usize, plug);
        if prev == plug {
            return Ok(());
        }
        let mut kvm_region = kvm_userspace_memory_region::from(mem_slot);
        if !plug {
            kvm_region.memory_size = 0;
        }
        vm.register_kvm_region(kvm_region)
    }
}

#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::cast_possible_truncation)]
impl GuestMemoryRegion for SlottedGuestMemoryRegion {
    type B = Option<AtomicBitmap>;

    fn len(&self) -> GuestUsize {
        self.region.len()
    }

    fn start_addr(&self) -> GuestAddress {
        self.region.start_addr()
    }

    fn bitmap(&self) -> &Self::B {
        self.region.bitmap()
    }

    fn get_host_address(
        &self,
        addr: MemoryRegionAddress,
    ) -> vm_memory::guest_memory::Result<*mut u8> {
        self.region.get_host_address(addr)
    }

    fn file_offset(&self) -> Option<&FileOffset> {
        self.region.file_offset()
    }

    fn get_slice(
        &self,
        offset: MemoryRegionAddress,
        count: usize,
    ) -> vm_memory::guest_memory::Result<VolatileSlice<'_, BS<'_, Self::B>>> {
        self.region.get_slice(offset, count)
    }
}

/// Creates a `Vec` of `GuestRegionMmap` with the given configuration
pub fn create(
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    mmap_flags: libc::c_int,
    file: Option<File>,
    track_dirty_pages: bool,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    let mut offset = 0;
    let file = file.map(Arc::new);
    regions
        .map(|(start, size)| {
            let mut builder = MmapRegionBuilder::new_with_bitmap(
                size,
                track_dirty_pages.then(|| AtomicBitmap::with_len(size)),
            )
            .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
            .with_mmap_flags(libc::MAP_NORESERVE | mmap_flags);

            if let Some(ref file) = file {
                let file_offset = FileOffset::from_arc(Arc::clone(file), offset);

                builder = builder.with_file_offset(file_offset);
            }

            offset = match offset.checked_add(size as u64) {
                None => return Err(MemoryError::OffsetTooLarge),
                Some(new_off) if new_off >= i64::MAX as u64 => {
                    return Err(MemoryError::OffsetTooLarge);
                }
                Some(new_off) => new_off,
            };

            GuestRegionMmap::new(
                builder.build().map_err(MemoryError::MmapRegionError)?,
                start,
            )
            .map_err(MemoryError::VmMemoryError)
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Creates a GuestMemoryMmap with `size` in MiB backed by a memfd.
pub fn memfd_backed(
    regions: &[(GuestAddress, usize)],
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    let size = regions.iter().map(|&(_, size)| size as u64).sum();
    let memfd_file = create_memfd(size, huge_pages.into())?.into_file();

    create(
        regions.iter().copied(),
        libc::MAP_SHARED | huge_pages.mmap_flags(),
        Some(memfd_file),
        track_dirty_pages,
    )
}

/// Creates a GuestMemoryMmap from raw regions.
pub fn anonymous(
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
    huge_pages: HugePageConfig,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    create(
        regions,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | huge_pages.mmap_flags(),
        None,
        track_dirty_pages,
    )
}

/// Creates a GuestMemoryMmap given a `file` containing the data
/// and a `state` containing mapping information.
pub fn snapshot_file(
    file: File,
    regions: impl Iterator<Item = (GuestAddress, usize)>,
    track_dirty_pages: bool,
) -> Result<Vec<GuestRegionMmap>, MemoryError> {
    create(regions, libc::MAP_PRIVATE, Some(file), track_dirty_pages)
}

/// Defines the interface for snapshotting memory.
pub trait GuestMemoryExtension
where
    Self: Sized,
{
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState;

    /// Mark memory range as dirty
    fn mark_dirty(&self, addr: GuestAddress, len: usize);

    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: WriteVolatile>(&self, writer: &mut T) -> Result<(), MemoryError>;

    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> Result<(), MemoryError>;

    /// Resets all the memory region bitmaps
    fn reset_dirty(&self);

    /// Store the dirty bitmap in internal store
    fn store_dirty_bitmap(&self, dirty_bitmap: &DirtyBitmap, page_size: usize);
}

/// State of a guest memory region saved to file/buffer.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryRegionState {
    // This should have been named `base_guest_addr` since it's _guest_ addr, but for
    // backward compatibility we have to keep this name. At least this comment should help.
    /// Base GuestAddress.
    pub base_address: u64,
    /// Region size.
    pub size: usize,
    /// Region type
    pub region_type: GuestRegionType,
    /// Plugged/unplugged status of each slot
    pub plugged: BitVec,
}

/// Describes guest memory regions and their snapshot file mappings.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestMemoryState {
    /// List of regions.
    pub regions: Vec<GuestMemoryRegionState>,
}

impl GuestMemoryState {
    /// Turns this [`GuestMemoryState`] into a description of guest memory regions as understood
    /// by the creation functions of [`GuestMemoryExtensions`]
    pub fn regions(&self) -> impl Iterator<Item = (GuestAddress, usize)> + '_ {
        self.regions
            .iter()
            .map(|region| (GuestAddress(region.base_address), region.size))
    }
}

impl GuestMemoryExtension for GuestMemoryMmap {
    /// Describes GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self) -> GuestMemoryState {
        let mut guest_memory_state = GuestMemoryState::default();
        self.iter().for_each(|region| {
            guest_memory_state.regions.push(GuestMemoryRegionState {
                base_address: region.start_addr().0,
                size: u64_to_usize(region.len()),
                region_type: region.region_type(),
                plugged: region.plugged.lock().unwrap().clone(),
            });
        });
        guest_memory_state
    }

    /// Mark memory range as dirty
    fn mark_dirty(&self, addr: GuestAddress, len: usize) {
        let _ = self.try_access(len, addr, |_total, count, caddr, region| {
            if let Some(bitmap) = region.bitmap() {
                bitmap.mark_dirty(u64_to_usize(caddr.0), count);
            }
            Ok(count)
        });
    }

    /// Dumps all contents of GuestMemoryMmap to a writer.
    fn dump<T: WriteVolatile>(&self, writer: &mut T) -> Result<(), MemoryError> {
        self.iter()
            .try_for_each(|region| Ok(writer.write_all_volatile(&region.as_volatile_slice()?)?))
            .map_err(MemoryError::WriteMemory)
    }

    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writer.
    fn dump_dirty<T: WriteVolatile + std::io::Seek>(
        &self,
        writer: &mut T,
        dirty_bitmap: &DirtyBitmap,
    ) -> Result<(), MemoryError> {
        let mut writer_offset = 0;
        let page_size = get_page_size().map_err(MemoryError::PageSize)?;

        let write_result = self
            .iter()
            .flat_map(|region| region.plugged_slots().map(move |slot| (region, slot)))
            .try_for_each(|(region, mem_slot)| {
                let kvm_bitmap = dirty_bitmap.get(&mem_slot.slot).unwrap();

                let firecracker_bitmap = region.bitmap();
                let mut write_size = 0;
                let mut dirty_batch_start: u64 = 0;

                for (i, v) in kvm_bitmap.iter().enumerate() {
                    for j in 0..64 {
                        let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;
                        let page_offset = ((i * 64) + j) * page_size + mem_slot.offset;
                        let is_firecracker_page_dirty = firecracker_bitmap.dirty_at(page_offset);

                        if is_kvm_page_dirty || is_firecracker_page_dirty {
                            // We are at the start of a new batch of dirty pages.
                            if write_size == 0 {
                                // Seek forward over the unmodified pages.
                                writer
                                    .seek(SeekFrom::Start(writer_offset + page_offset as u64))
                                    .unwrap();
                                dirty_batch_start = page_offset as u64;
                            }
                            write_size += page_size;
                        } else if write_size > 0 {
                            // We are at the end of a batch of dirty pages.
                            writer.write_all_volatile(
                                &region.get_slice(
                                    MemoryRegionAddress(dirty_batch_start),
                                    write_size,
                                )?,
                            )?;

                            write_size = 0;
                        }
                    }
                }

                if write_size > 0 {
                    writer.write_all_volatile(
                        &region.get_slice(MemoryRegionAddress(dirty_batch_start), write_size)?,
                    )?;
                }
                writer_offset += region.len();
                Ok(())
            });

        if write_result.is_err() {
            self.store_dirty_bitmap(dirty_bitmap, page_size);
        } else {
            self.reset_dirty();
        }

        write_result.map_err(MemoryError::WriteMemory)
    }

    /// Resets all the memory region bitmaps
    fn reset_dirty(&self) {
        self.iter().for_each(|region| {
            if let Some(bitmap) = region.bitmap() {
                bitmap.reset();
            }
        })
    }

    /// Stores the dirty bitmap inside into the internal bitmap
    fn store_dirty_bitmap(&self, dirty_bitmap: &DirtyBitmap, page_size: usize) {
        self.iter()
            .flat_map(|region| region.plugged_slots().map(move |slot| (region, slot)))
            .for_each(|(region, mem_slot)| {
                let kvm_bitmap = dirty_bitmap.get(&mem_slot.slot).unwrap();
                let firecracker_bitmap = region.bitmap();

                for (i, v) in kvm_bitmap.iter().enumerate() {
                    for j in 0..64 {
                        let is_kvm_page_dirty = ((v >> j) & 1u64) != 0u64;

                        if is_kvm_page_dirty {
                            let page_offset = ((i * 64) + j) * page_size + mem_slot.offset;

                            firecracker_bitmap.mark_dirty(page_offset, 1)
                        }
                    }
                }
            });
    }
}

fn create_memfd(
    mem_size: u64,
    hugetlb_size: Option<memfd::HugetlbSize>,
) -> Result<memfd::Memfd, MemoryError> {
    // Create a memfd.
    let opts = memfd::MemfdOptions::default()
        .hugetlb(hugetlb_size)
        .allow_sealing(true);
    let mem_file = opts.create("guest_mem").map_err(MemoryError::Memfd)?;

    // Resize to guest mem size.
    mem_file
        .as_file()
        .set_len(mem_size)
        .map_err(MemoryError::MemfdSetLen)?;

    // Add seals to prevent further resizing.
    let mut seals = memfd::SealsHashSet::new();
    seals.insert(memfd::FileSeal::SealShrink);
    seals.insert(memfd::FileSeal::SealGrow);
    mem_file.add_seals(&seals).map_err(MemoryError::Memfd)?;

    // Prevent further sealing changes.
    mem_file
        .add_seal(memfd::FileSeal::SealSeal)
        .map_err(MemoryError::Memfd)?;

    Ok(mem_file)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks)]

    use std::collections::HashMap;
    use std::io::{Read, Seek, SeekFrom};

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::snapshot::Snapshot;
    use crate::utils::{get_page_size, mib_to_bytes};

    fn into_slotted_region(regions: Vec<GuestRegionMmap>) -> GuestMemoryMmap {
        GuestMemoryMmap::from_regions(
            regions
                .into_iter()
                .zip(0u32..) // assign dummy slots
                .map(|(region, slot)| SlottedGuestMemoryRegion::dram_from_mmap_region(region, slot))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn test_anonymous() {
        for dirty_page_tracking in [true, false] {
            let region_size = 0x10000;
            let regions = vec![
                (GuestAddress(0x0), region_size),
                (GuestAddress(0x10000), region_size),
                (GuestAddress(0x20000), region_size),
                (GuestAddress(0x30000), region_size),
            ];

            let guest_memory = anonymous(
                regions.into_iter(),
                dirty_page_tracking,
                HugePageConfig::None,
            )
            .unwrap();
            guest_memory.iter().for_each(|region| {
                assert_eq!(region.bitmap().is_some(), dirty_page_tracking);
            });
        }
    }

    #[test]
    fn test_mark_dirty() {
        let page_size = get_page_size().unwrap();
        let region_size = page_size * 3;

        let regions = vec![
            (GuestAddress(0), region_size),                      // pages 0-2
            (GuestAddress(region_size as u64), region_size),     // pages 3-5
            (GuestAddress(region_size as u64 * 2), region_size), // pages 6-8
        ];
        let guest_memory = into_slotted_region(
            anonymous(regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );

        let dirty_map = [
            // page 0: not dirty
            (0, page_size, false),
            // pages 1-2: dirty range in one region
            (page_size, page_size * 2, true),
            // page 3: not dirty
            (page_size * 3, page_size, false),
            // pages 4-7: dirty range across 2 regions,
            (page_size * 4, page_size * 4, true),
            // page 8: not dirty
            (page_size * 8, page_size, false),
        ];

        // Mark dirty memory
        for (addr, len, dirty) in &dirty_map {
            if *dirty {
                guest_memory.mark_dirty(GuestAddress(*addr as u64), *len);
            }
        }

        // Check that the dirty memory was set correctly
        for (addr, len, dirty) in &dirty_map {
            guest_memory
                .try_access(
                    *len,
                    GuestAddress(*addr as u64),
                    |_total, count, caddr, region| {
                        let offset = usize::try_from(caddr.0).unwrap();
                        let bitmap = region.bitmap().as_ref().unwrap();
                        for i in offset..offset + count {
                            assert_eq!(bitmap.dirty_at(i), *dirty);
                        }
                        Ok(count)
                    },
                )
                .unwrap();
        }
    }

    fn check_serde<M: GuestMemoryExtension>(guest_memory: &M) {
        let mut snapshot_data = vec![0u8; 10000];
        let original_state = guest_memory.describe();
        Snapshot::new(&original_state)
            .save(&mut snapshot_data.as_mut_slice())
            .unwrap();
        let restored_state = Snapshot::load_without_crc_check(snapshot_data.as_slice())
            .unwrap()
            .data;
        assert_eq!(original_state, restored_state);
    }

    #[test]
    fn test_serde() {
        let page_size = get_page_size().unwrap();
        let region_size = page_size * 3;

        // Test with a single region
        let guest_memory = into_slotted_region(
            anonymous(
                [(GuestAddress(0), region_size)].into_iter(),
                false,
                HugePageConfig::None,
            )
            .unwrap(),
        );
        check_serde(&guest_memory);

        // Test with some regions
        let regions = vec![
            (GuestAddress(0), region_size),                      // pages 0-2
            (GuestAddress(region_size as u64), region_size),     // pages 3-5
            (GuestAddress(region_size as u64 * 2), region_size), // pages 6-8
        ];
        let guest_memory = into_slotted_region(
            anonymous(regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );
        check_serde(&guest_memory);
    }

    #[test]
    fn test_describe() {
        let page_size: usize = get_page_size().unwrap();

        // Two regions of one page each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size),
            (GuestAddress(page_size as u64 * 2), page_size),
        ];
        let guest_memory = into_slotted_region(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size,
                    region_type: GuestRegionType::Dram,
                    plugged: BitVec::repeat(true, 1),
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 2,
                    size: page_size,
                    region_type: GuestRegionType::Dram,
                    plugged: BitVec::repeat(true, 1),
                },
            ],
        };

        let actual_memory_state = guest_memory.describe();
        assert_eq!(expected_memory_state, actual_memory_state);

        // Two regions of three pages each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size * 3),
            (GuestAddress(page_size as u64 * 4), page_size * 3),
        ];
        let guest_memory = into_slotted_region(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size * 3,
                    region_type: GuestRegionType::Dram,
                    plugged: BitVec::repeat(true, 1),
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 4,
                    size: page_size * 3,
                    region_type: GuestRegionType::Dram,
                    plugged: BitVec::repeat(true, 1),
                },
            ],
        };

        let actual_memory_state = guest_memory.describe();
        assert_eq!(expected_memory_state, actual_memory_state);
    }

    #[test]
    fn test_dump() {
        let page_size = get_page_size().unwrap();

        // Two regions of two pages each, with a one page gap between them.
        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(page_size as u64 * 3);
        let region_size = page_size * 2;
        let mem_regions = [
            (region_1_address, region_size),
            (region_2_address, region_size),
        ];
        let guest_memory = into_slotted_region(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );
        // Check that Firecracker bitmap is clean.
        guest_memory.iter().for_each(|r| {
            assert!(!r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(1));
        });

        // Fill the first region with 1s and the second with 2s.
        let first_region = vec![1u8; region_size];
        guest_memory.write(&first_region, region_1_address).unwrap();

        let second_region = vec![2u8; region_size];
        guest_memory
            .write(&second_region, region_2_address)
            .unwrap();

        let memory_state = guest_memory.describe();

        // dump the full memory.
        let mut memory_file = TempFile::new().unwrap().into_file();
        guest_memory.dump(&mut memory_file).unwrap();

        let restored_guest_memory =
            into_slotted_region(snapshot_file(memory_file, memory_state.regions(), false).unwrap());

        // Check that the region contents are the same.
        let mut restored_region = vec![0u8; page_size * 2];
        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_1_address)
            .unwrap();
        assert_eq!(first_region, restored_region);

        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_2_address)
            .unwrap();
        assert_eq!(second_region, restored_region);
    }

    #[test]
    fn test_dump_dirty() {
        let page_size = get_page_size().unwrap();

        // Two regions of two pages each, with a one page gap between them.
        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(page_size as u64 * 3);
        let region_size = page_size * 2;
        let mem_regions = [
            (region_1_address, region_size),
            (region_2_address, region_size),
        ];
        let guest_memory = into_slotted_region(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );
        // Check that Firecracker bitmap is clean.
        guest_memory.iter().for_each(|r| {
            assert!(!r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(1));
        });

        // Fill the first region with 1s and the second with 2s.
        let first_region = vec![1u8; region_size];
        guest_memory.write(&first_region, region_1_address).unwrap();

        let second_region = vec![2u8; region_size];
        guest_memory
            .write(&second_region, region_2_address)
            .unwrap();

        let memory_state = guest_memory.describe();

        // Dump only the dirty pages.
        // First region pages: [dirty, clean]
        // Second region pages: [clean, dirty]
        let mut dirty_bitmap: DirtyBitmap = HashMap::new();
        dirty_bitmap.insert(0, vec![0b01]);
        dirty_bitmap.insert(1, vec![0b10]);

        let mut file = TempFile::new().unwrap().into_file();
        guest_memory.dump_dirty(&mut file, &dirty_bitmap).unwrap();

        // We can restore from this because this is the first dirty dump.
        let restored_guest_memory =
            into_slotted_region(snapshot_file(file, memory_state.regions(), false).unwrap());

        // Check that the region contents are the same.
        let mut restored_region = vec![0u8; region_size];
        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_1_address)
            .unwrap();
        assert_eq!(first_region, restored_region);

        restored_guest_memory
            .read(restored_region.as_mut_slice(), region_2_address)
            .unwrap();
        assert_eq!(second_region, restored_region);

        // Dirty the memory and dump again
        let file = TempFile::new().unwrap();
        let mut reader = file.into_file();
        let zeros = vec![0u8; page_size];
        let ones = vec![1u8; page_size];
        let twos = vec![2u8; page_size];

        // Firecracker Bitmap
        // First region pages: [dirty, clean]
        // Second region pages: [clean, clean]
        guest_memory
            .write(&twos, GuestAddress(page_size as u64))
            .unwrap();

        guest_memory.dump_dirty(&mut reader, &dirty_bitmap).unwrap();

        // Check that only the dirty regions are dumped.
        let mut diff_file_content = Vec::new();
        let expected_first_region = [
            ones.as_slice(),
            twos.as_slice(),
            zeros.as_slice(),
            twos.as_slice(),
        ]
        .concat();
        reader.seek(SeekFrom::Start(0)).unwrap();
        reader.read_to_end(&mut diff_file_content).unwrap();
        assert_eq!(expected_first_region, diff_file_content);
    }

    #[test]
    fn test_store_dirty_bitmap() {
        let page_size = get_page_size().unwrap();

        // Two regions of three pages each, with a one page gap between them.
        let region_1_address = GuestAddress(0);
        let region_2_address = GuestAddress(page_size as u64 * 4);
        let region_size = page_size * 3;
        let mem_regions = [
            (region_1_address, region_size),
            (region_2_address, region_size),
        ];
        let guest_memory = into_slotted_region(
            anonymous(mem_regions.into_iter(), true, HugePageConfig::None).unwrap(),
        );

        // Check that Firecracker bitmap is clean.
        guest_memory.iter().for_each(|r| {
            assert!(!r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(page_size));
            assert!(!r.bitmap().dirty_at(page_size * 2));
        });

        let mut dirty_bitmap: DirtyBitmap = HashMap::new();
        dirty_bitmap.insert(0, vec![0b101]);
        dirty_bitmap.insert(1, vec![0b101]);

        guest_memory.store_dirty_bitmap(&dirty_bitmap, page_size);

        // Assert that the bitmap now reports as being dirty maching the dirty bitmap
        guest_memory.iter().for_each(|r| {
            assert!(r.bitmap().dirty_at(0));
            assert!(!r.bitmap().dirty_at(page_size));
            assert!(r.bitmap().dirty_at(page_size * 2));
        });
    }

    #[test]
    fn test_create_memfd() {
        let size_bytes = mib_to_bytes(1) as u64;

        let memfd = create_memfd(size_bytes, None).unwrap();

        assert_eq!(memfd.as_file().metadata().unwrap().len(), size_bytes);
        memfd.as_file().set_len(0x69).unwrap_err();

        let mut seals = memfd::SealsHashSet::new();
        seals.insert(memfd::FileSeal::SealGrow);
        memfd.add_seals(&seals).unwrap_err();
    }
}
