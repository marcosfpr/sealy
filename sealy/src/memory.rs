use crate::error::{convert_seal_error, Result};
use std::{ffi::c_void, ptr::null_mut};

use crate::bindgen;

/// Memory pool handle for SEAL.
///
/// Heavily incomplete and work in progress.
#[derive(Debug)]
pub struct MemoryPool {
	pub(crate) handle: *mut c_void,
}

unsafe impl Sync for MemoryPool {}
unsafe impl Send for MemoryPool {}

impl MemoryPool {
	/// Creates an instance of MemoryPool.
	pub fn new() -> Result<Self> {
		let mut handle: *mut c_void = null_mut();

		convert_seal_error(unsafe { bindgen::MemoryPoolHandle_New(true, &mut handle) })?;

		Ok(MemoryPool {
			handle,
		})
	}

	/// Returns handle to the underlying SEAL object.
	pub fn get_handle(&self) -> *mut c_void {
		self.handle
	}
}

impl Drop for MemoryPool {
	fn drop(&mut self) {
		convert_seal_error(unsafe { bindgen::MemoryPoolHandle_Destroy(self.handle) })
			.expect("Internal error in MemoryPool::drop().");
	}
}

#[cfg(test)]
mod tests {
	use crate::*;

	#[test]
	fn can_create_and_destroy_memory_pool() {
		let memory_pool = MemoryPool::new().unwrap();

		std::mem::drop(memory_pool);
	}
}
