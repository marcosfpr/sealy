use crate::{error::Result, try_seal};
use std::{
	ffi::c_void,
	ptr::null_mut,
	sync::atomic::{AtomicPtr, Ordering},
};

use crate::bindgen;

/// Memory pool handle for SEAL.
///
/// The purpose of a custom memory management is to save allocation/deallocation overhead.
/// SEAL has a significant runtime overhead caused by memory allocation/deallocation due to
/// the large amount of memory space required by SEAL. The custom memory pool is designed to
/// reduce this overhead by providing a way to allocate memory in advance and reuse it.
///
/// In the FFI, the memory pool is read-only and cannot be modified. The memory pool is
/// initialized by the library and is used by the library to allocate memory. The methods
/// provided by this crate are just to check the pool's health and status.
#[derive(Debug)]
pub struct MemoryPool {
	/// A pointer to the underlying SEAL memory pool.
	pub(crate) handle: AtomicPtr<c_void>,
}

impl MemoryPool {
	/// Creates an empty SEAL memory pool.
	pub fn new() -> Result<Self> {
		let mut handle: *mut c_void = null_mut();
		let clear_on_destruction = true;

		try_seal!(unsafe { bindgen::MemoryPoolHandle_New(clear_on_destruction, &mut handle) })?;

		Ok(MemoryPool {
			handle: AtomicPtr::new(handle),
		})
	}

	/// Returns the number of allocations in the pool.
	pub fn pool_count(&self) -> Result<u64> {
		let mut count: u64 = 0;

		try_seal!(unsafe { bindgen::MemoryPoolHandle_PoolCount(self.get_handle(), &mut count) })?;

		Ok(count)
	}

	/// Returns the number of bytes allocated in the pool.
	pub fn pool_allocated_byte_count(&self) -> Result<u64> {
		let mut count: u64 = 0;

		try_seal!(unsafe {
			bindgen::MemoryPoolHandle_AllocByteCount(self.get_handle(), &mut count)
		})?;

		Ok(count)
	}

	/// Returns the number of bytes used in the pool.
	pub fn pool_used_byte_count(&self) -> Result<i64> {
		let mut count: i64 = 0;

		try_seal!(unsafe { bindgen::MemoryPoolHandle_UseCount(self.get_handle(), &mut count) })?;

		Ok(count)
	}

	/// Returns true if the pool is initialized.
	pub fn is_initialized(&self) -> Result<bool> {
		let mut result: bool = false;

		try_seal!(unsafe {
			bindgen::MemoryPoolHandle_IsInitialized(self.get_handle(), &mut result)
		})?;

		Ok(result)
	}

	/// Returns handle to the underlying SEAL object.
	pub(crate) unsafe fn get_handle(&self) -> *mut c_void {
		self.handle.load(Ordering::SeqCst)
	}
}

impl Drop for MemoryPool {
	fn drop(&mut self) {
		if let Err(err) = try_seal!(unsafe { bindgen::MemoryPoolHandle_Destroy(self.get_handle()) })
		{
			panic!("Failed to destroy memory pool: {:?}", err);
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::*;

	#[test]
	fn can_create_and_destroy_memory_pool() {
		let memory_pool = MemoryPool::new().unwrap();
		assert!(memory_pool.is_initialized().unwrap());
		std::mem::drop(memory_pool);
	}

	#[test]
	fn can_get_pool_count() {
		let memory_pool = MemoryPool::new().unwrap();
		let count = memory_pool.pool_count().unwrap();
		let is_initialized = memory_pool.is_initialized().unwrap();
		assert_eq!(count, 0);
		assert!(is_initialized);
	}
}
