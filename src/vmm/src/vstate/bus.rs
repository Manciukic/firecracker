// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//! Handles routing to devices in an address space.

use std::cmp::Ordering;
use std::collections::btree_map::BTreeMap;
use std::sync::{Arc, Barrier, Mutex, RwLock, Weak};

use slab::Slab;

/// Trait for devices that respond to reads or writes in an arbitrary address space.
///
/// The device does not care where it exists in address space as each method is only given an offset
/// into its allocated portion of address space.
#[allow(unused_variables)]
pub trait BusDevice: Send {
    /// Reads at `offset` from this device
    fn read(&mut self, base: u64, offset: u64, data: &mut [u8]) {}
    /// Writes at `offset` into this device
    fn write(&mut self, base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
        None
    }
}

/// Error type for [`Bus`]-related operations.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BusError {
    /// The insertion failed because the new device overlapped with an old device.
    Overlap,
    /// Failed to operate on zero sized range.
    ZeroSizedRange,
    /// Failed to find address range.
    MissingAddressRange,
    /// The supplied range is invalid.
    InvalidRange,
}

/// Holds a base and end representing the address space occupied by a `BusDevice`.
///
/// * base - The address at which the range start.
/// * end - The last address of the range (inclusive).
#[derive(Debug, Copy, Clone)]
pub struct BusRange {
    /// base address of a range within a [`Bus`]
    base: u64,
    /// last address of a range within a [`Bus`] (inclusive)
    end: u64,
}

#[allow(missing_docs)]
impl BusRange {
    pub fn new(base: u64, len: u64) -> Result<Self, BusError> {
        if len == 0 {
            return Err(BusError::ZeroSizedRange);
        }
        let end = base.checked_add(len - 1).ok_or(BusError::InvalidRange)?;
        Ok(BusRange { base, end })
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn end(&self) -> u64 {
        self.end
    }

    /// Returns true if there is overlap with the given range.
    pub fn overlaps(&self, other: &BusRange) -> bool {
        self.base <= other.end && other.base <= self.end
    }
}

impl Eq for BusRange {}

impl PartialEq for BusRange {
    fn eq(&self, other: &BusRange) -> bool {
        self.base == other.base
    }
}

impl Ord for BusRange {
    fn cmp(&self, other: &BusRange) -> Ordering {
        self.base.cmp(&other.base)
    }
}

impl PartialOrd for BusRange {
    fn partial_cmp(&self, other: &BusRange) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Identifies a device registered with a [`Bus`].
///
/// This is an opaque, [`Copy`] handle rather than a pointer: holding one keeps nothing alive, so it
/// cannot be used to resurrect a device that has been removed. Using a slot that has been removed
/// simply fails with [`BusError::MissingAddressRange`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BusSlot(usize);

/// A device container for routing reads and writes over some address space.
///
/// This doesn't have any restrictions on what kind of device or address space this applies to. The
/// only restriction is that no two devices can overlap in this address space.
///
/// # Locking
///
/// The two roles of the bus - *owning* devices and *routing* addresses to them - are deliberately
/// kept behind separate locks, in this order:
///
/// ```text
/// devices (outer) -> ranges (inner) -> device mutex
/// ```
///
/// * `devices` is held for the whole duration of a device access. It is therefore the point at
///   which [`Bus::remove_device`] drains in-flight accesses: once its write lock is acquired, no
///   thread can be inside a device operation, so no other thread can be holding a reference to the
///   device afterwards. Note the bus itself only ever holds a [`Weak`], so it is never an owner.
/// * `ranges` is only ever held for the routing lookup itself and is dropped before the device is
///   touched. Because of that, a device operation may take `ranges.write()` - which is what makes
///   PCI BAR relocation possible from a vCPU thread that is already inside a device write.
///
/// The ordering above must never be inverted: acquiring `devices` while holding `ranges` would
/// reintroduce an AB/BA deadlock against [`Bus::remove_device`].
///
/// # Rules for callers
///
/// Because `devices` is held across a device access, and a device access needs the device's own
/// mutex, the following two rules avoid deadlocking against a concurrent access:
///
/// 1. **Do not hold a device's mutex while calling [`Bus::add_device`], [`Bus::insert`] or
///    [`Bus::remove_device`].** Those take `devices.write()`, while a thread already inside a device
///    access holds `devices.read()` and may be waiting for the very mutex you hold - a classic
///    AB/BA deadlock. Collect whatever you need from the device in a scope that ends before the
///    call, as `attach_common()` and `detach_pci_virtio_device()` do.
/// 2. **A [`BusDevice::read`] or [`BusDevice::write`] implementation must not add or remove a
///    *device* on the bus it is being accessed through**, as that needs `devices.write()` while this
///    thread already holds `devices.read()`, which self-deadlocks.
///
/// Neither rule applies to the range operations ([`Bus::insert_range`], [`Bus::remove_range`],
/// [`Bus::relocate_range`]): they only take `ranges`, so they are safe to call both from within a
/// device operation and while holding a device mutex.
#[derive(Default, Debug)]
pub struct Bus {
    /// Devices owned by this bus, indexed by [`BusSlot`].
    ///
    /// `Weak` is load-bearing and must not be turned into `Arc`: a [`Bus`] lives inside `KvmVm`,
    /// while some devices hold an `Arc<KvmVm>` of their own (e.g. virtio-pmem and virtio-mem), so
    /// owning the devices here would close a reference cycle and leak the whole VM.
    devices: RwLock<Slab<Weak<Mutex<dyn BusDevice>>>>,
    /// Address ranges mapped onto the devices above. Routing only.
    ranges: RwLock<BTreeMap<BusRange, BusSlot>>,
}

impl Bus {
    /// Constructs an a bus with an empty address space.
    pub fn new() -> Bus {
        Bus {
            devices: RwLock::new(Slab::new()),
            ranges: RwLock::new(BTreeMap::new()),
        }
    }

    /// Registers a device with the [`Bus`] without mapping any address range to it.
    ///
    /// Use [`Bus::insert_range`] to make the device reachable.
    pub fn add_device(&self, device: Arc<Mutex<dyn BusDevice>>) -> BusSlot {
        BusSlot(
            self.devices
                .write()
                .unwrap()
                .insert(Arc::downgrade(&device)),
        )
    }

    /// Maps the range [`base`, `base` + `len`) onto an already registered device.
    pub fn insert_range(&self, slot: BusSlot, base: u64, len: u64) -> Result<(), BusError> {
        let new_range = BusRange::new(base, len)?;

        let mut ranges = self.ranges.write().unwrap();

        // Reject all cases where the new range overlaps with an existing one. Checked under the
        // same lock as the insertion below, so two concurrent callers cannot both succeed.
        if ranges.keys().any(|range| range.overlaps(&new_range)) {
            return Err(BusError::Overlap);
        }

        ranges.insert(new_range, slot);

        Ok(())
    }

    /// Registers a device and maps the range [`base`, `base` + `len`) onto it.
    pub fn insert(
        &self,
        device: Arc<Mutex<dyn BusDevice>>,
        base: u64,
        len: u64,
    ) -> Result<BusSlot, BusError> {
        // Validate the range before taking a slot, so a bad range cannot leak one.
        BusRange::new(base, len)?;

        let slot = self.add_device(device);
        match self.insert_range(slot, base, len) {
            Ok(()) => Ok(slot),
            Err(err) => {
                // Roll back, otherwise the slot would be leaked for the lifetime of the bus. The
                // slot was just created here so this cannot fail, but report the original error
                // regardless rather than masking it.
                let rollback = self.remove_device(slot);
                debug_assert!(rollback.is_ok());
                Err(err)
            }
        }
    }

    /// Unmaps the given address range, leaving the device registered.
    ///
    /// Only takes the `ranges` lock, so this is callable from within a device operation.
    pub fn remove_range(&self, base: u64, len: u64) -> Result<(), BusError> {
        let bus_range = BusRange::new(base, len)?;

        if self.ranges.write().unwrap().remove(&bus_range).is_none() {
            return Err(BusError::MissingAddressRange);
        }

        Ok(())
    }

    /// Moves an already mapped range to `new_base`, keeping its length and device.
    ///
    /// Only takes the `ranges` lock, so this is callable from within a device operation - which is
    /// what PCI BAR relocation needs, as it is driven by a guest write to a BAR register.
    pub fn relocate_range(&self, old_base: u64, new_base: u64, len: u64) -> Result<(), BusError> {
        let old_range = BusRange::new(old_base, len)?;
        let new_range = BusRange::new(new_base, len)?;

        let mut ranges = self.ranges.write().unwrap();

        let &slot = ranges
            .get(&old_range)
            .ok_or(BusError::MissingAddressRange)?;

        // The destination must be free, ignoring the range we are about to vacate.
        if ranges
            .keys()
            .any(|range| range != &old_range && range.overlaps(&new_range))
        {
            return Err(BusError::Overlap);
        }

        ranges.remove(&old_range);
        ranges.insert(new_range, slot);

        Ok(())
    }

    /// Removes a device from the [`Bus`], along with every range mapped onto it.
    ///
    /// Acquiring the `devices` write lock waits for all in-flight device accesses to finish, so
    /// once this returns no other thread can hold a reference to the device and the caller is free
    /// to drop it.
    pub fn remove_device(&self, slot: BusSlot) -> Result<(), BusError> {
        // Lock order: `devices` before `ranges`.
        let mut devices = self.devices.write().unwrap();

        if !devices.contains(slot.0) {
            return Err(BusError::MissingAddressRange);
        }

        // Drop the routing entries before freeing the slot, so that the slot index cannot be
        // recycled by a later `add_device()` while a stale range still points at it.
        self.ranges
            .write()
            .unwrap()
            .retain(|_range, mapped| *mapped != slot);

        devices.remove(slot.0);

        Ok(())
    }

    // Lock the `devices` behind `read` lock, lock the device mutex and perform an operation on the
    // device.
    fn with_device<T>(
        &self,
        addr: u64,
        f: impl FnOnce(&mut dyn BusDevice, u64, u64) -> T,
    ) -> Result<T, BusError> {
        // Outer lock, held for the whole access: this is what `remove_device()` drains against.
        let devices = self.devices.read().unwrap();

        // Inner lock, dropped as soon as the lookup is done. Only `Copy` data escapes it, so a
        // device operation is free to take `ranges.write()` (e.g. to relocate a BAR).
        let (slot, base, offset) = {
            let ranges = self.ranges.read().unwrap();
            let (range, &slot) = ranges
                .range(..=BusRange::new(addr, 1)?)
                .next_back()
                .ok_or(BusError::MissingAddressRange)?;
            if addr > range.end() {
                return Err(BusError::MissingAddressRange);
            }
            (slot, range.base(), addr - range.base())
        };

        // The upgraded `Arc` is a temporary that never escapes this frame.
        let device = devices
            .get(slot.0)
            .and_then(Weak::upgrade)
            .ok_or(BusError::MissingAddressRange)?;
        let mut device = device.lock().unwrap();

        Ok(f(&mut *device, base, offset))
    }

    /// Reads data from the device that owns the range containing `addr` and puts it into `data`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> Result<(), BusError> {
        self.with_device(addr, |dev, base, offset| dev.read(base, offset, data))
    }

    /// Writes `data` to the device that owns the range containing `addr`.
    ///
    /// Returns true on success, otherwise `data` is untouched.
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<Option<Arc<Barrier>>, BusError> {
        self.with_device(addr, |dev, base, offset| dev.write(base, offset, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyDevice;
    impl BusDevice for DummyDevice {}

    /// Takes long enough in `read()` that another thread can reliably observe the access in flight.
    struct SlowDevice;
    impl BusDevice for SlowDevice {
        fn read(&mut self, _base: u64, _offset: u64, _data: &mut [u8]) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    struct ConstantDevice;
    impl BusDevice for ConstantDevice {
        #[allow(clippy::cast_possible_truncation)]
        fn read(&mut self, _base: u64, offset: u64, data: &mut [u8]) {
            for (i, v) in data.iter_mut().enumerate() {
                *v = (offset as u8) + (i as u8);
            }
        }

        #[allow(clippy::cast_possible_truncation)]
        fn write(&mut self, _base: u64, offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
            for (i, v) in data.iter().enumerate() {
                assert_eq!(*v, (offset as u8) + (i as u8))
            }

            None
        }
    }

    #[test]
    fn bus_range_new() {
        // Zero length is invalid.
        assert!(matches!(BusRange::new(0, 0), Err(BusError::ZeroSizedRange)));
        assert!(matches!(
            BusRange::new(u64::MAX, 0),
            Err(BusError::ZeroSizedRange)
        ));

        // Overflow is invalid.
        assert!(matches!(
            BusRange::new(u64::MAX, 2),
            Err(BusError::InvalidRange)
        ));
        assert!(matches!(
            BusRange::new(2, u64::MAX),
            Err(BusError::InvalidRange)
        ));

        // Ranges that exactly reach u64::MAX are valid.
        let r = BusRange::new(u64::MAX, 1).unwrap();
        assert_eq!(r.base(), u64::MAX);
        assert_eq!(r.end(), u64::MAX);

        let r = BusRange::new(1, u64::MAX).unwrap();
        assert_eq!(r.base(), 1);
        assert_eq!(r.end(), u64::MAX);

        let r = BusRange::new(u64::MAX - 4095, 4096).unwrap();
        assert_eq!(r.base(), u64::MAX - 4095);
        assert_eq!(r.end(), u64::MAX);

        // One sized valid range.
        let r = BusRange::new(0, 1).unwrap();
        assert_eq!(r.base(), 0);
        assert_eq!(r.end(), 0);

        // Normal valid range.
        let r = BusRange::new(0x1000, 0x400).unwrap();
        assert_eq!(r.base(), 0x1000);
        assert_eq!(r.end(), 0x13ff);
    }

    #[test]
    fn bus_insert() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        bus.insert(dummy.clone(), 0x10, 0).unwrap_err();
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();

        let result = bus.insert(dummy.clone(), 0x0f, 0x10);
        assert_eq!(format!("{result:?}"), "Err(Overlap)");

        bus.insert(dummy.clone(), 0x10, 0x10).unwrap_err();
        bus.insert(dummy.clone(), 0x10, 0x15).unwrap_err();
        bus.insert(dummy.clone(), 0x12, 0x15).unwrap_err();
        bus.insert(dummy.clone(), 0x12, 0x01).unwrap_err();
        bus.insert(dummy.clone(), 0x0, 0x20).unwrap_err();
        bus.insert(dummy.clone(), 0x20, 0x05).unwrap();
        bus.insert(dummy.clone(), 0x25, 0x05).unwrap();
        bus.insert(dummy, 0x0, 0x10).unwrap();
    }

    #[test]
    fn bus_remove_range() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));

        bus.remove_range(0x42, 0x0).unwrap_err();

        bus.remove_range(0x13, 0x12).unwrap_err();

        bus.insert(dummy.clone(), 0x13, 0x12).unwrap();
        bus.remove_range(0x42, 0x42).unwrap_err();
        bus.remove_range(0x13, 0x12).unwrap();

        // The range is gone, so the device is no longer reachable.
        bus.read(0x13, &mut [0]).unwrap_err();
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn bus_read_write() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();
        bus.read(0x10, &mut [0, 0, 0, 0]).unwrap();
        bus.write(0x10, &[0, 0, 0, 0]).unwrap();
        bus.read(0x11, &mut [0, 0, 0, 0]).unwrap();
        bus.write(0x11, &[0, 0, 0, 0]).unwrap();
        bus.read(0x16, &mut [0, 0, 0, 0]).unwrap();
        bus.write(0x16, &[0, 0, 0, 0]).unwrap();
        bus.read(0x20, &mut [0, 0, 0, 0]).unwrap_err();
        bus.write(0x20, &[0, 0, 0, 0]).unwrap_err();
        bus.read(0x06, &mut [0, 0, 0, 0]).unwrap_err();
        bus.write(0x06, &[0, 0, 0, 0]).unwrap_err();
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn bus_read_write_values() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(ConstantDevice));
        bus.insert(dummy.clone(), 0x10, 0x10).unwrap();

        let mut values = [0, 1, 2, 3];
        bus.read(0x10, &mut values).unwrap();
        assert_eq!(values, [0, 1, 2, 3]);
        bus.write(0x10, &values).unwrap();
        bus.read(0x15, &mut values).unwrap();
        assert_eq!(values, [5, 6, 7, 8]);
        bus.write(0x15, &values).unwrap();
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn busrange_cmp() {
        let range = BusRange::new(0x10, 2).unwrap();
        assert_eq!(range, BusRange::new(0x10, 3).unwrap());
        assert_eq!(range, BusRange::new(0x10, 2).unwrap());

        assert!(range < BusRange::new(0x12, 1).unwrap());
        assert!(range < BusRange::new(0x12, 3).unwrap());

        assert_eq!(range, range.clone());

        let bus = Bus::new();
        let mut data = [1, 2, 3, 4];
        let device = Arc::new(Mutex::new(DummyDevice));
        bus.insert(device.clone(), 0x10, 0x10).unwrap();
        bus.write(0x10, &data).unwrap();
        bus.read(0x10, &mut data).unwrap();
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    fn bus_remove_device() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));

        let slot = bus.insert(dummy.clone(), 0x10, 0x10).unwrap();
        bus.read(0x10, &mut [0]).unwrap();

        bus.remove_device(slot).unwrap();

        // Removing the device also unmapped its range.
        bus.read(0x10, &mut [0]).unwrap_err();
        bus.remove_range(0x10, 0x10).unwrap_err();

        // Removing a slot twice is an error rather than a panic.
        bus.remove_device(slot).unwrap_err();
    }

    /// A slot freed by `remove_device()` may be handed out again. Make sure a range left over from
    /// the previous occupant can never route to the new one.
    #[test]
    fn bus_slot_reuse() {
        let bus = Bus::new();
        let first = Arc::new(Mutex::new(DummyDevice));
        let second = Arc::new(Mutex::new(ConstantDevice));

        let first_slot = bus.insert(first.clone(), 0x10, 0x10).unwrap();
        bus.remove_device(first_slot).unwrap();

        // The slab is free to reuse the index here.
        let second_slot = bus.insert(second.clone(), 0x100, 0x10).unwrap();

        // Whether or not the index was recycled, the old address must not resolve, and the new
        // device must serve its own range.
        bus.read(0x10, &mut [0]).unwrap_err();
        let mut data = [0, 0, 0, 0];
        bus.read(0x105, &mut data).unwrap();
        assert_eq!(data, [5, 6, 7, 8]);

        bus.remove_device(second_slot).unwrap();
    }

    /// A device that relocates its own range from inside a bus write.
    ///
    /// This is the shape of PCI BAR relocation: the guest writes a BAR register, which is handled on
    /// a vCPU thread that is already inside `Bus::write()`. Before the ownership and routing locks
    /// were split, taking the write lock here deadlocked against the read lock held by the caller.
    struct RelocatingDevice {
        bus: Weak<Bus>,
        len: u64,
    }

    impl BusDevice for RelocatingDevice {
        fn write(&mut self, base: u64, _offset: u64, data: &[u8]) -> Option<Arc<Barrier>> {
            let bus = self.bus.upgrade().unwrap();
            let new_base = u64::from(data[0]) << 8;
            bus.relocate_range(base, new_base, self.len).unwrap();
            None
        }
    }

    #[test]
    fn bus_relocate_from_device_write() {
        let bus = Arc::new(Bus::new());
        let device = Arc::new(Mutex::new(RelocatingDevice {
            bus: Arc::downgrade(&bus),
            len: 0x10,
        }));

        bus.insert(device.clone(), 0x1000, 0x10).unwrap();

        // Ask the device to move itself to 0x400. If the routing lock were the same lock held
        // across the device access, this would deadlock instead of returning.
        bus.write(0x1000, &[0x04]).unwrap();

        // The device answers at its new address and no longer at the old one.
        bus.read(0x400, &mut [0]).unwrap();
        bus.read(0x1000, &mut [0]).unwrap_err();
    }

    #[test]
    fn bus_relocate_range() {
        let bus = Bus::new();
        let dummy = Arc::new(Mutex::new(DummyDevice));
        let other = Arc::new(Mutex::new(DummyDevice));

        bus.insert(dummy.clone(), 0x1000, 0x100).unwrap();
        bus.insert(other.clone(), 0x2000, 0x100).unwrap();

        // Unmapped source.
        bus.relocate_range(0x5000, 0x6000, 0x100).unwrap_err();
        // Destination overlaps a different device.
        bus.relocate_range(0x1000, 0x2080, 0x100).unwrap_err();
        // The original mapping survived the failed attempts.
        bus.read(0x1000, &mut [0]).unwrap();

        // Relocating onto itself is a no-op, not a spurious overlap.
        bus.relocate_range(0x1000, 0x1000, 0x100).unwrap();
        bus.read(0x1000, &mut [0]).unwrap();

        bus.relocate_range(0x1000, 0x3000, 0x100).unwrap();
        bus.read(0x3000, &mut [0]).unwrap();
        bus.read(0x1000, &mut [0]).unwrap_err();
        // The range we vacated is now free to take.
        bus.relocate_range(0x2000, 0x1000, 0x100).unwrap();
    }

    /// A range operation is safe to perform while holding a device's mutex, because it only takes
    /// the `ranges` lock. This is what lets the attach/detach paths keep working, and what BAR
    /// relocation relies on.
    ///
    /// The device-level operations are *not* safe that way - see the "Rules for callers" section on
    /// [`Bus`]. That is why `attach_common()` scopes its device lock so it is released before the
    /// bus insertion.
    #[test]
    fn bus_range_ops_safe_while_holding_device_mutex() {
        let bus = Arc::new(Bus::new());
        let accessed = Arc::new(Mutex::new(SlowDevice));
        let other = Arc::new(Mutex::new(DummyDevice));

        bus.insert(accessed.clone(), 0x10, 0x10).unwrap();
        let other_slot = bus.add_device(other.clone());

        let start = Arc::new(Barrier::new(2));

        let reader = {
            let bus = Arc::clone(&bus);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                bus.read(0x10, &mut [0; 4]).unwrap();
            })
        };

        // Hold the device mutex the reader is about to block on, then map a range. If range
        // operations took the `devices` lock, this would deadlock against the reader.
        let guard = accessed.lock().unwrap();
        start.wait();
        bus.insert_range(other_slot, 0x100, 0x10).unwrap();
        drop(guard);

        reader.join().unwrap();
    }

    /// Regression test for a guest-triggerable VMM panic (CWE-362): a vCPU thread accessing a
    /// device while the VMM thread unplugs it used to trip an `assert_eq!` on the device's
    /// reference count. `remove_device()` now drains in-flight accesses instead.
    #[test]
    fn bus_unplug_races_with_access() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

        for _ in 0..100 {
            let bus = Arc::new(Bus::new());
            let device = Arc::new(Mutex::new(ConstantDevice));
            let slot = bus.insert(device.clone(), 0x10, 0x10).unwrap();

            let stop = Arc::new(AtomicBool::new(false));

            let reader = {
                let bus = Arc::clone(&bus);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(AtomicOrdering::Relaxed) {
                        // Either the device is still mapped and answers, or it is gone and we get
                        // MissingAddressRange. Both are fine; a panic or a hang is not.
                        let _ = bus.read(0x10, &mut [0, 0, 0, 0]);
                    }
                })
            };

            bus.remove_device(slot).unwrap();

            // The unplug has drained all accesses, so we are the last owner and the device is
            // dropped here rather than by whichever thread happened to touch it last.
            assert_eq!(Arc::strong_count(&device), 1);

            stop.store(true, AtomicOrdering::Relaxed);
            reader.join().unwrap();
        }
    }

    #[test]
    fn bus_range_overlap() {
        let a = BusRange::new(0x1000, 0x400).unwrap();
        assert!(a.overlaps(&BusRange::new(0x1000, 0x400).unwrap()));
        assert!(a.overlaps(&BusRange::new(0xf00, 0x400).unwrap()));
        assert!(a.overlaps(&BusRange::new(0x1000, 0x01).unwrap()));
        assert!(a.overlaps(&BusRange::new(0xfff, 0x02).unwrap()));
        assert!(a.overlaps(&BusRange::new(0x1100, 0x100).unwrap()));
        assert!(a.overlaps(&BusRange::new(0x13ff, 0x100).unwrap()));
        assert!(!a.overlaps(&BusRange::new(0x1400, 0x100).unwrap()));
        assert!(!a.overlaps(&BusRange::new(0xf00, 0x100).unwrap()));
    }
}
