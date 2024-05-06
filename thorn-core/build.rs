fn main() -> Result<(), Box<dyn std::error::Error>> {
	println!("Compiling proto files...");

	tonic_build::configure()
		.build_client(true)
		.build_server(true)
		.compile(
			&[
				"proto/thorn/driver.proto",
				"proto/thorn/error.proto",
				"proto/thorn/fleet.proto",
				"proto/thorn/node.proto",
				"proto/thorn/task.proto",
				"proto/thorn/coordinator.proto",
				"proto/thorn/recordset.proto",
			],
			&["proto/thorn"],
		)?;

	Ok(())
}
