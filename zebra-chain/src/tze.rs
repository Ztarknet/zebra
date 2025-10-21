use crate::{
    amount::{Amount, NonNegative},
    transparent::OutPoint,
};

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(test, feature = "proptest-impl", feature = "elasticsearch"),
    derive(Serialize)
)]
pub struct ExtensionData {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(test, feature = "proptest-impl", feature = "elasticsearch"),
    derive(Serialize)
)]
pub struct Input {
    pub prevout: OutPoint,
    pub witness: ExtensionPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(test, feature = "proptest-impl", feature = "elasticsearch"),
    derive(Serialize)
)]
pub struct Output {
    pub value: Amount<NonNegative>,
    pub precondition: ExtensionPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(test, feature = "proptest-impl", feature = "elasticsearch"),
    derive(Serialize)
)]
pub struct ExtensionPayload {
    pub extension_id: u32,
    pub mode: u32,
    pub payload: Vec<u8>,
}
