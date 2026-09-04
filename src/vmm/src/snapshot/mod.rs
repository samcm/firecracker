// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provides serialization and deserialization facilities and implements a persistent storage
//! format for Firecracker state snapshots.
//!
//! The `Snapshot` API manages serialization and deserialization of collections of objects
//! that implement the `serde` `Serialize`, `Deserialize` trait. Currently, we use
//! [`bitcode`](https://docs.rs/bitcode/latest/bitcode/) for performing the serialization.
//!
//! The snapshot format uses the following layout:
//!
//!  |-----------------------------|
//!  |       64 bit magic_id       |
//!  |-----------------------------|
//!  |       version string        |
//!  |-----------------------------|
//!  |            State            |
//!  |-----------------------------|
//!  |        optional CRC64       |
//!  |-----------------------------|
//!
//!
//! The snapshot format uses a version value in the form of `MAJOR.MINOR.PATCH`, defined by
//! [`SNAPSHOT_VERSION`].
pub mod crc;
mod persist;
use std::fmt::Debug;
use std::io::{Read, Write};

use crc64::crc64;
use semver::Version;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::snapshot::crc::CRC64Writer;
pub use crate::snapshot::persist::Persist;

/// Version of the snapshot format produced and accepted by this crate.
///
/// The major version was raised for the farplane fork: `VsockFrontendState` carries the
/// transport-reset gate and its acknowledgement watermark. The version is what a build of this
/// same layout compares before it uses the state; a snapshot of a *different* layout never
/// reaches that check, because the version is encoded inside the structure and bitcode requires
/// exact types, so decoding fails first. Either way the state is refused rather than decoded into
/// something else, and neither path reports a foreign layout's version.
pub const SNAPSHOT_VERSION: Version = Version::new(12, 0, 0);

#[cfg(target_arch = "x86_64")]
const SNAPSHOT_MAGIC_ID: u64 = 0x0710_1984_8664_0000u64;

#[cfg(target_arch = "aarch64")]
const SNAPSHOT_MAGIC_ID: u64 = 0x0710_1984_AAAA_0000u64;

/// Maximum size in bytes for snapshot serialization and deserialization.
///
/// Farplane advertises this same bound as its capture-buffer capacity. Keeping one limit means
/// every vmstate Firecracker can produce is also one it can restore.
pub const SNAPSHOT_DESERIALIZATION_BYTES_LIMIT: usize = 16 << 20;

/// Error definitions for the Snapshot API.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SnapshotError {
    /// CRC64 validation failed
    Crc64,
    /// Invalid data version: {0}
    InvalidFormatVersion(Version),
    /// Magic value does not match arch: {0}
    InvalidMagic(u64),
    /// An error occurred during bitcode serialization: {0}
    Bitcode(#[from] bitcode::Error),
    /// IO Error: {0}
    Io(#[from] std::io::Error),
    /// Snapshot size exceeds limit of {0} bytes
    SizeLimitExceeded(usize),
    /// Snapshot was produced under feature identity {found}, but this build is {expected}
    IncompatibleFeatureIdentity {
        /// Identity of the binary reading the snapshot.
        expected: String,
        /// Identity recorded by the binary that produced the snapshot.
        found: String,
    },
}

fn serialize<S: Serialize, W: Write>(data: &S, write: &mut W) -> Result<(), SnapshotError> {
    let encoded = bitcode::serialize(data)?;
    write.write_all(&encoded).map_err(SnapshotError::Io)
}

/// Firecracker snapshot header
#[derive(Debug, Serialize, Deserialize)]
struct SnapshotHdr {
    /// magic value
    magic: u64,
    /// Snapshot data version
    version: Version,
    /// Feature identity of the binary that produced this snapshot.
    ///
    /// The identity the handshake reports proves only what is running now. A restore reads state
    /// another binary wrote, so the identity travels with the state and is checked before that
    /// state is used for anything: the capture order, the quiesce semantics and the vmstate layout
    /// it names are properties of the image, not of the process reading it.
    feature_identity: String,
}

/// Assumes the raw bytes stream read from the given [`Read`] instance is a snapshot file,
/// and returns the version of it.
pub fn get_format_version<R: Read>(reader: &mut R) -> Result<Version, SnapshotError> {
    // Check size limit before reading the full file to prevent DOS attacks
    let mut buf = Vec::new();
    let bytes_read = reader
        .take((SNAPSHOT_DESERIALIZATION_BYTES_LIMIT + 1) as u64)
        .read_to_end(&mut buf)?;

    if bytes_read > SNAPSHOT_DESERIALIZATION_BYTES_LIMIT {
        return Err(SnapshotError::SizeLimitExceeded(
            SNAPSHOT_DESERIALIZATION_BYTES_LIMIT,
        ));
    }

    // The last 8 bytes are the CRC, so we need to separate them for deserialization
    if buf.len() < 8 {
        return Err(SnapshotError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "File too short to contain CRC",
        )));
    }

    let (data_buf, _crc_buf) = buf.split_at(buf.len() - 8);

    // Since bitcode requires exact type matching, we need to try deserializing
    // as the specific snapshot type we know about. In practice, all snapshots
    // in Firecracker use MicrovmState as the data type.
    use crate::persist::MicrovmState;

    match bitcode::deserialize::<Snapshot<MicrovmState>>(data_buf) {
        Ok(snapshot) => Ok(snapshot.header.version),
        Err(e) => {
            // If deserialization fails, it could be due to:
            // 1. The snapshot was created with bincode (older versions)
            // 2. The MicrovmState structure has changed and is incompatible
            // 3. The snapshot file is corrupted
            // Since supporting bincode is out of scope, we return a descriptive error.
            Err(SnapshotError::Bitcode(e))
        }
    }
}

/// Firecracker snapshot type
///
/// A type used to store and load Firecracker snapshots of a particular version
#[derive(Debug, Serialize, Deserialize)]
pub struct Snapshot<Data> {
    header: SnapshotHdr,
    /// The data stored int his [`Snapshot`]
    pub data: Data,
}

impl<Data> Snapshot<Data> {
    /// Constructs a new snapshot with the given `data`.
    pub fn new(data: Data) -> Self {
        Self {
            header: SnapshotHdr {
                magic: SNAPSHOT_MAGIC_ID,
                version: SNAPSHOT_VERSION.clone(),
                feature_identity: crate::vstate::farplane::FEATURE_IDENTITY.to_string(),
            },
            data,
        }
    }

    /// Gets the version of this snapshot
    pub fn version(&self) -> &Version {
        &self.header.version
    }
}

impl<Data: DeserializeOwned> Snapshot<Data> {
    pub(crate) fn load_without_crc_check(buf: &[u8]) -> Result<Self, SnapshotError> {
        // Check size limit to prevent DOS attacks
        if buf.len() > SNAPSHOT_DESERIALIZATION_BYTES_LIMIT {
            return Err(SnapshotError::SizeLimitExceeded(
                SNAPSHOT_DESERIALIZATION_BYTES_LIMIT,
            ));
        }

        let snapshot: Self = bitcode::deserialize(buf)?;

        // Validate the header
        if snapshot.header.magic != SNAPSHOT_MAGIC_ID {
            return Err(SnapshotError::InvalidMagic(snapshot.header.magic));
        }

        if snapshot.header.version.major != SNAPSHOT_VERSION.major
            || snapshot.header.version.minor > SNAPSHOT_VERSION.minor
        {
            return Err(SnapshotError::InvalidFormatVersion(
                snapshot.header.version.clone(),
            ));
        }

        // Checked with the rest of the header, which is before the state is handed to a caller:
        // guest memory is mapped from a plan the caller only builds once this returns.
        if snapshot.header.feature_identity != crate::vstate::farplane::FEATURE_IDENTITY {
            return Err(SnapshotError::IncompatibleFeatureIdentity {
                expected: crate::vstate::farplane::FEATURE_IDENTITY.to_string(),
                found: snapshot.header.feature_identity.clone(),
            });
        }

        Ok(snapshot)
    }

    /// Loads a snapshot from the given [`Read`] instance, performing all validations
    /// (CRC, snapshot magic value, snapshot version).
    pub fn load<R: Read>(reader: &mut R) -> Result<Self, SnapshotError> {
        // Check size limit before reading the full file to prevent DOS attacks
        let mut buf = Vec::new();
        let bytes_read = reader
            .take((SNAPSHOT_DESERIALIZATION_BYTES_LIMIT + 1) as u64)
            .read_to_end(&mut buf)?;

        if bytes_read > SNAPSHOT_DESERIALIZATION_BYTES_LIMIT {
            return Err(SnapshotError::SizeLimitExceeded(
                SNAPSHOT_DESERIALIZATION_BYTES_LIMIT,
            ));
        }

        // The last 8 bytes are the CRC, so we need to separate them
        if buf.len() < 8 {
            return Err(SnapshotError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "File too short to contain CRC",
            )));
        }

        let (data_buf, _crc_buf) = buf.split_at(buf.len() - 8);
        let snapshot = Self::load_without_crc_check(data_buf)?;

        let computed_checksum = crc64(0, buf.as_slice());
        // When we read the entire file, we also read the checksum into the buffer. The CRC has the
        // property that crc(0, buf.as_slice()) == 0 iff the last 8 bytes of buf are the checksum
        // of all the preceding bytes, and this is the property we are using here.
        if computed_checksum != 0 {
            return Err(SnapshotError::Crc64);
        }
        Ok(snapshot)
    }
}

impl<Data: Serialize> Snapshot<Data> {
    /// Saves `self` to the given [`Write`] instance, computing the CRC of the written data,
    /// and then writing the CRC into the `Write` instance, too.
    pub fn save<W: Write>(&self, writer: &mut W) -> Result<(), SnapshotError> {
        let mut crc_writer = CRC64Writer::new(writer);
        serialize(self, &mut crc_writer)?;
        // Write the CRC as raw bytes, not bitcode-serialized
        crc_writer
            .writer
            .write_all(&crc_writer.checksum().to_le_bytes())
            .map_err(SnapshotError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::MicrovmState;

    #[test]
    fn test_snapshot_restore() {
        let state = MicrovmState::default();
        let mut buf = Vec::new();

        Snapshot::new(state).save(&mut buf).unwrap();
        Snapshot::<MicrovmState>::load(&mut buf.as_slice()).unwrap();
    }

    /// A snapshot this build produced carries this build's identity, and is accepted.
    #[test]
    fn a_snapshot_of_this_identity_is_accepted() {
        let mut buf = Vec::new();
        let snapshot = Snapshot::new(MicrovmState::default());
        assert_eq!(
            snapshot.header.feature_identity,
            crate::vstate::farplane::FEATURE_IDENTITY
        );
        assert_eq!(snapshot.header.feature_identity, "farplane/4");

        snapshot.save(&mut buf).unwrap();

        let loaded = Snapshot::<MicrovmState>::load(&mut buf.as_slice()).unwrap();
        assert_eq!(loaded.header.feature_identity, "farplane/4");
    }

    /// A warm image baked by an older identity is refused before its state is used: the capture
    /// order and the vmstate layout that identity named are not the ones this build reads.
    #[test]
    fn a_snapshot_of_an_older_identity_is_refused() {
        let mut snapshot = Snapshot::new(MicrovmState::default());
        snapshot.header.feature_identity = "farplane/1".to_string();
        let mut buf = Vec::new();
        snapshot.save(&mut buf).unwrap();

        let err = Snapshot::<MicrovmState>::load(&mut buf.as_slice()).unwrap_err();
        match err {
            SnapshotError::IncompatibleFeatureIdentity { expected, found } => {
                assert_eq!(found, "farplane/1");
                assert_eq!(expected, "farplane/4");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// The version this fork produces, and what the version check is for: an image whose state
    /// this build can decode, carrying a version it does not accept, is refused before that state
    /// is used. The header here is the only foreign thing about the image, which is what isolates
    /// the check.
    #[test]
    fn the_format_version_refuses_a_decodable_image_of_another_version() {
        assert_eq!(SNAPSHOT_VERSION, Version::new(12, 0, 0));

        let mut snapshot = Snapshot::new(MicrovmState::default());
        snapshot.header.version = Version::new(10, 0, 0);
        let mut buf = Vec::new();
        snapshot.save(&mut buf).unwrap();

        assert!(matches!(
            Snapshot::<MicrovmState>::load(&mut buf.as_slice()),
            Err(SnapshotError::InvalidFormatVersion(version)) if version == Version::new(10, 0, 0)
        ));
    }

    /// A warm image of an older layout, such as one from before the transport-reset gate entered
    /// `VsockFrontendState`, is not what the version check refuses. bitcode is positional and
    /// requires exact types, and the version sits inside the encoded structure, so the decode
    /// fails before any header field is available. The refusal is what the fork needs, and this
    /// records the shape of it: no version is reported for such an image, by `load` or by
    /// `firecracker --describe-snapshot`.
    ///
    /// The stand-in below is a foreign layout rather than a reconstruction of a specific older
    /// one: this build has no older `MicrovmState` to instantiate, and the behaviour under test
    /// belongs to every layout that is not this build's.
    #[test]
    fn a_snapshot_of_a_foreign_layout_is_refused_without_a_version() {
        #[derive(Serialize)]
        struct ForeignLayout {
            header: SnapshotHdr,
            data: (u64, String),
        }

        let image = bitcode::serialize(&ForeignLayout {
            header: SnapshotHdr {
                magic: SNAPSHOT_MAGIC_ID,
                version: Version::new(11, 0, 0),
                feature_identity: "farplane/2".to_string(),
            },
            data: (7, "state this build cannot decode".to_string()),
        })
        .unwrap();

        assert!(
            matches!(
                Snapshot::<MicrovmState>::load_without_crc_check(&image),
                Err(SnapshotError::Bitcode(_))
            ),
            "a foreign layout must be refused outright rather than decoded"
        );

        // What `--describe-snapshot` reads. The trailing eight bytes are where a snapshot file
        // carries its CRC, which this reader splits off before decoding.
        let mut file = image;
        file.extend_from_slice(&[0u8; 8]);
        assert!(
            matches!(
                get_format_version(&mut std::io::Cursor::new(&file)),
                Err(SnapshotError::Bitcode(_))
            ),
            "the version of a foreign layout is not reportable, and must not be invented"
        );
    }

    #[test]
    fn test_parse_version_from_file() {
        use crate::persist::MicrovmState;
        let snapshot = Snapshot::new(MicrovmState::default());

        // Use a Vec<u8> that can grow as needed
        let mut snapshot_data = Vec::new();
        snapshot.save(&mut snapshot_data).unwrap();

        assert_eq!(
            get_format_version(&mut std::io::Cursor::new(&snapshot_data)).unwrap(),
            SNAPSHOT_VERSION
        );
    }

    #[test]
    fn test_bad_reader() {
        #[derive(Debug)]
        struct BadReader;

        impl Read for BadReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::InvalidInput.into())
            }
        }

        let mut reader = BadReader {};

        assert!(
            matches!(Snapshot::<()>::load(&mut reader), Err(SnapshotError::Io(inner)) if inner.kind() == std::io::ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn test_bad_magic() {
        // Create a snapshot with corrupted magic and serialize it properly
        let mut bad_snapshot = Snapshot::new(());
        bad_snapshot.header.magic = 0xDEADBEEF;

        // Serialize the bad snapshot (without CRC for load_without_crc_check)
        let corrupted_data = bitcode::serialize(&bad_snapshot).unwrap();

        assert!(matches!(
            Snapshot::<()>::load_without_crc_check(&corrupted_data),
            Err(SnapshotError::InvalidMagic(_))
        ));
    }

    #[test]
    fn test_bad_crc() {
        let snapshot = Snapshot::new(());

        // Use a Vec<u8> that can grow as needed
        let mut valid_data = Vec::new();
        snapshot.save(&mut valid_data).unwrap();

        // Corrupt the CRC by changing the last 8 bytes (where CRC is stored)
        if valid_data.len() >= 8 {
            for i in (valid_data.len() - 8)..valid_data.len() {
                valid_data[i] ^= 0xFF; // Corrupt the CRC by flipping bits
            }
        }

        assert!(matches!(
            Snapshot::<()>::load(&mut std::io::Cursor::new(&valid_data)),
            Err(SnapshotError::Crc64)
        ));
    }

    #[test]
    fn test_bad_version() {
        // Different major version: shouldn't work
        let mut bad_snapshot = Snapshot::new(());
        bad_snapshot.header.version.major = SNAPSHOT_VERSION.major + 1;
        let data = bitcode::serialize(&bad_snapshot).unwrap();

        assert!(matches!(
            Snapshot::<()>::load_without_crc_check(&data),
            Err(SnapshotError::InvalidFormatVersion(v)) if v.major == SNAPSHOT_VERSION.major + 1
        ));

        //  minor > SNAPSHOT_VERSION.minor: shouldn't work
        let mut bad_snapshot = Snapshot::new(());
        bad_snapshot.header.version.minor = SNAPSHOT_VERSION.minor + 1;
        let data = bitcode::serialize(&bad_snapshot).unwrap();
        assert!(matches!(
            Snapshot::<()>::load_without_crc_check(&data),
            Err(SnapshotError::InvalidFormatVersion(v)) if v.minor == SNAPSHOT_VERSION.minor + 1
        ));

        // But we can support minor versions smaller or equal to ours. We also support
        // all patch versions within our supported major.minor version.
        let snapshot = Snapshot::new(());
        let data = bitcode::serialize(&snapshot).unwrap();
        Snapshot::<()>::load_without_crc_check(&data).unwrap();

        if SNAPSHOT_VERSION.minor != 0 {
            let mut snapshot = Snapshot::new(());
            snapshot.header.version.minor = SNAPSHOT_VERSION.minor - 1;
            let data = bitcode::serialize(&snapshot).unwrap();
            Snapshot::<()>::load_without_crc_check(&data).unwrap();
        }

        let mut snapshot = Snapshot::new(());
        snapshot.header.version.patch = 0;
        let data = bitcode::serialize(&snapshot).unwrap();
        Snapshot::<()>::load_without_crc_check(&data).unwrap();

        let mut snapshot = Snapshot::new(());
        snapshot.header.version.patch = SNAPSHOT_VERSION.patch + 1;
        let data = bitcode::serialize(&snapshot).unwrap();
        Snapshot::<()>::load_without_crc_check(&data).unwrap();

        let mut snapshot = Snapshot::new(());
        snapshot.header.version.patch = 1024;
        let data = bitcode::serialize(&snapshot).unwrap();
        Snapshot::<()>::load_without_crc_check(&data).unwrap();
    }
}
