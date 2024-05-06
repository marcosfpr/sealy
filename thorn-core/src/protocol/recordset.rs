//! This module contains re-exports from the generated protocol buffers code.
//!
//! The generated code is not meant to be used directly, but rather through the re-exports in this module.
use super::autogen::thorn_proto;

/// A list of double values.
pub use thorn_proto::DoubleList;

/// A list of signed 64-bit integer values.
pub use thorn_proto::Sint64List;

/// A list of boolean values.
pub use thorn_proto::BoolList;

/// A list of string values.
pub use thorn_proto::StringList;

/// A list of bytes values.
pub use thorn_proto::BytesList;

/// A tensor of values
pub use thorn_proto::Array;

/// A metric value.
pub use thorn_proto::MetricsRecordValue;

/// A config value.
pub use thorn_proto::ConfigsRecordValue;

/// Parameters record.
pub use thorn_proto::ParametersRecord;

/// Metrics record.
pub use thorn_proto::MetricsRecord;

/// Config record.
pub use thorn_proto::ConfigsRecord;

/// RecordSet is a collection of parameters record, metrics record, and config record.
pub use thorn_proto::RecordSet;
