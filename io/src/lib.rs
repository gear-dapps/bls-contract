#![no_std]

use gmeta::{In, InOut, Metadata};
use gstd::{prelude::*, ActorId};

#[derive(Encode, Decode, TypeInfo, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug)]
pub enum Action {
    Verify(Verify),
    VerifyHashes(VerifyHashes)
}

#[derive(Encode, Decode, TypeInfo, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug)]
pub struct Verify {
    pub signature: Vec<u8>,
    pub messages: Vec<Vec<u8>>,
    pub public_keys: Vec<Vec<u8>>,
}

#[derive(Encode, Decode, TypeInfo, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug)]
pub struct VerifyHashes {
    pub signature: Vec<u8>,
    pub hashes: Vec<Vec<Vec<Vec<u64>>>>,
    pub public_keys: Vec<Vec<u8>>,
}

#[derive(Encode, Decode, TypeInfo, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]
pub enum Event {
    Verified,
    NotVerified,
}

#[derive(Encode, Decode, TypeInfo, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug)]
pub enum Error {
    PreviousTxMustBeCompleted,
}

pub struct ContractMetadata;

impl Metadata for ContractMetadata {
    type Init = In<()>;
    type Handle = InOut<Action, Event>;
    type Others = ();
    type Reply = ();
    type Signal = ();
    type State = State;
}

#[derive(Encode, Decode, TypeInfo, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug, Default)]
pub struct State {
    pub transactions: BTreeMap<ActorId, Transaction<Action>>,
    pub current_tid: TransactionId,
}

pub type TransactionId = u64;

#[derive(Encode, Decode, TypeInfo, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Debug)]
pub struct Transaction<T> {
    pub transaction_id: TransactionId,
    pub action: T,
}
