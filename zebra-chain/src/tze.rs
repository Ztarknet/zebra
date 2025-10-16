//! Transparent Zcash Extension (TZE) data structures.
//!
//! These types mirror the serialization layout defined in ZIP-222.

use std::{fmt, io};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::{
    amount::{Amount, NonNegative},
    block::MAX_BLOCK_BYTES,
    serialization::{
        zcash_serialize_bytes, CompactSize64, ReadZcashExt, SerializationError, TrustedPreallocate,
        ZcashDeserialize, ZcashSerialize,
    },
    transaction,
};

/// The minimal serialized size of a `Data` structure:
/// - `tze_id` encoded as a CompactSize varint (at least 1 byte),
/// - `tze_mode` encoded as a CompactSize varint (at least 1 byte),
/// - payload length encoded as a CompactSize varint (at least 1 byte).
pub(crate) const MIN_TZE_DATA_SIZE: u64 = 3;

/// The minimal serialized size of a [`TzeIn`].
pub(crate) const MIN_TZE_INPUT_SIZE: u64 = 32 + 4 + MIN_TZE_DATA_SIZE;

/// The minimal serialized size of a [`TzeOut`].
pub(crate) const MIN_TZE_OUTPUT_SIZE: u64 = 8 + MIN_TZE_DATA_SIZE;

/// Identifier allocated to a specific transparent extension.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ExtensionId(pub u64);

/// Mode identifier scoped to a [`ExtensionId`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Mode(pub u64);

/// Serialized payload shared by TZE inputs and outputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Data {
    /// Extension identifier (`tze_id` in ZIP-222).
    pub extension_id: ExtensionId,
    /// Mode identifier (`tze_mode` in ZIP-222).
    pub mode: Mode,
    /// Mode-specific payload.
    pub payload: Vec<u8>,
}

impl Data {
    /// Returns `true` if the payload is empty.
    pub fn payload_is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

impl ZcashSerialize for Data {
    fn zcash_serialize<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        CompactSize64::from(self.extension_id.0).zcash_serialize(&mut writer)?;
        CompactSize64::from(self.mode.0).zcash_serialize(&mut writer)?;
        zcash_serialize_bytes(&self.payload, &mut writer)
    }
}

impl ZcashDeserialize for Data {
    fn zcash_deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let extension_id = CompactSize64::zcash_deserialize(&mut reader)?;
        let mode = CompactSize64::zcash_deserialize(&mut reader)?;
        let payload = Vec::zcash_deserialize(&mut reader)?;

        Ok(Data {
            extension_id: ExtensionId(u64::from(extension_id)),
            mode: Mode(u64::from(mode)),
            payload,
        })
    }
}

/// Outpoint reference for a TZE output.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct OutPoint {
    /// Transaction hash containing the referenced TZE output.
    pub hash: transaction::Hash,
    /// Output index within the transaction.
    pub index: u32,
}

impl OutPoint {
    /// Returns a new [`OutPoint`] from an in-memory output `index`.
    ///
    /// # Panics
    ///
    /// If `index` doesn't fit in a [`u32`].
    pub fn from_usize(hash: transaction::Hash, index: usize) -> OutPoint {
        OutPoint {
            hash,
            index: index
                .try_into()
                .expect("valid in-memory output indexes fit in a u32"),
        }
    }
}

impl ZcashSerialize for OutPoint {
    fn zcash_serialize<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        writer.write_all(&self.hash.0)?;
        writer.write_u32::<LittleEndian>(self.index)?;
        Ok(())
    }
}

impl ZcashDeserialize for OutPoint {
    fn zcash_deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let hash = transaction::Hash(reader.read_32_bytes()?);
        let index = reader.read_u32::<LittleEndian>()?;
        Ok(Self { hash, index })
    }
}

/// Witness data used to satisfy a previously published precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TzeIn {
    /// Reference to the committed precondition.
    pub prevout: OutPoint,
    /// Witness payload to be evaluated by the extension.
    pub witness: Data,
}

impl fmt::Display for TzeIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("tze::TzeIn")
            .field("prevout", &self.prevout)
            .field("witness", &self.witness)
            .finish()
    }
}

impl ZcashSerialize for TzeIn {
    fn zcash_serialize<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        self.prevout.zcash_serialize(&mut writer)?;
        self.witness.zcash_serialize(&mut writer)
    }
}

impl ZcashDeserialize for TzeIn {
    fn zcash_deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        Ok(Self {
            prevout: OutPoint::zcash_deserialize(&mut reader)?,
            witness: Data::zcash_deserialize(&mut reader)?,
        })
    }
}

/// A TZE output containing spendable value encumbered by a precondition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TzeOut {
    /// Spendable value protected by the extension precondition.
    pub value: Amount<NonNegative>,
    /// Extension-defined precondition payload.
    pub precondition: Data,
}

impl fmt::Display for TzeOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("tze::TzeOut")
            .field("value", &self.value)
            .field("precondition", &self.precondition)
            .finish()
    }
}

impl ZcashSerialize for TzeOut {
    fn zcash_serialize<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        writer.write_i64::<LittleEndian>(self.value.into())?;
        self.precondition.zcash_serialize(&mut writer)
    }
}

impl ZcashDeserialize for TzeOut {
    fn zcash_deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        let value = Amount::try_from(reader.read_i64::<LittleEndian>()?)
            .map_err(|_| SerializationError::Parse("invalid non-negative TZE value"))?;
        Ok(Self {
            value,
            precondition: Data::zcash_deserialize(&mut reader)?,
        })
    }
}

/// Collection of TZE inputs and outputs embedded in a transaction.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Bundle {
    /// Witnesses spending prior TZE outputs.
    pub inputs: Vec<TzeIn>,
    /// Newly created TZE outputs.
    pub outputs: Vec<TzeOut>,
}

impl fmt::Display for Bundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("tze::Bundle")
            .field("inputs", &self.inputs.len())
            .field("outputs", &self.outputs.len())
            .finish()
    }
}

impl ZcashSerialize for Bundle {
    fn zcash_serialize<W: io::Write>(&self, mut writer: W) -> Result<(), io::Error> {
        self.inputs.zcash_serialize(&mut writer)?;
        self.outputs.zcash_serialize(&mut writer)
    }
}

impl ZcashDeserialize for Bundle {
    fn zcash_deserialize<R: io::Read>(mut reader: R) -> Result<Self, SerializationError> {
        Ok(Self {
            inputs: Vec::zcash_deserialize(&mut reader)?,
            outputs: Vec::zcash_deserialize(&mut reader)?,
        })
    }
}

impl TrustedPreallocate for TzeIn {
    fn max_allocation() -> u64 {
        MAX_BLOCK_BYTES / MIN_TZE_INPUT_SIZE
    }
}

impl TrustedPreallocate for TzeOut {
    fn max_allocation() -> u64 {
        MAX_BLOCK_BYTES / MIN_TZE_OUTPUT_SIZE
    }
}

impl TrustedPreallocate for Bundle {
    fn max_allocation() -> u64 {
        1
    }
}

/// Convenience helper to produce an empty bundle.
pub fn empty_bundle() -> Bundle {
    Bundle::default()
}
