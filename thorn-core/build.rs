fn main() {
	tonic_build::compile_protos("proto/thorn/recordset.proto").unwrap();
	tonic_build::compile_protos("proto/thorn/node.proto").unwrap();
	tonic_build::compile_protos("proto/thorn/error.proto").unwrap();
	tonic_build::compile_protos("proto/thorn/task.proto").unwrap();
	tonic_build::compile_protos("proto/thorn/driver.proto").unwrap();
	tonic_build::compile_protos("proto/thorn/fleet.proto").unwrap();
	tonic_build::compile_protos("proto/thorn/coordinator.proto").unwrap();
}
