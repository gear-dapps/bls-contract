use crate::key::PublicKey;
use crate::signature::{self, Signature};
use app_io::*;
use bls12_381::G2Projective;
use gmeta::Metadata;
use gstd::{
    errors::{ContractError, Result as GstdResult},
    msg,
    prelude::*,
    util, ActorId, MessageId,
};

/// Написать контракт с принимающий на вход адреса пользователей и который будет верифицировать адреса пользователей с помощью библиотеки
/// Контракт проверяет подпись (Signature)

#[derive(Debug, Clone)]
pub struct Contract {
    pub transactions: BTreeMap<ActorId, Transaction<Action>>,
    pub current_tid: TransactionId,
}

static mut CONTRACT: Option<Contract> = None;

fn static_mut_state() -> &'static mut Contract {
    match unsafe { &mut CONTRACT } {
        Some(state) => state,
        None => unreachable!("State can't be uninitialized"),
    }
}

#[no_mangle]
extern "C" fn init() {
    unsafe {
        CONTRACT = Some(Contract {
            transactions: Default::default(),
            current_tid: 0,
        })
    }
}

#[no_mangle]
extern "C" fn handle() {
    process_handle()
        .expect("Failed to load, decode, encode, or reply with `PingPong` from `handle()`")
}

fn process_handle() -> Result<(), ContractError> {
    let mut contract = unsafe { CONTRACT.clone().unwrap() };

    let action: Action = msg::load().expect("Could not load Action");
    let msg_source = msg::source();

    let _reply: Result<Event, Error> = Err(Error::PreviousTxMustBeCompleted);
    let _transaction_id = if let Some(Transaction {
        transaction_id,
        action: pend_action,
    }) = contract.transactions.get(&msg_source)
    {
        if action != *pend_action {
            reply(_reply).expect("Failed to encode or reply with `Result<Event, Error>`");
            return Ok(());
        }
        *transaction_id
    } else {
        let transaction_id = contract.current_tid;
        contract.current_tid = contract.current_tid.wrapping_add(1);
        contract.transactions.insert(
            msg_source,
            Transaction {
                transaction_id,
                action: action.clone(),
            },
        );
        transaction_id
    };
    // gstd::debug!(
    //     "AZOYAN Action = {:?}, gas = {}",
    //     action,
    //     gstd::exec::gas_available()
    // );
    let result = match action {
        Action::Verify(Verify {
            signature,
            messages,
            public_keys,
        }) => {
            let signature = Signature::from_uncompressed_bytes(&signature).unwrap();
            // gstd::debug!(
            //     "AZOYAN deserialized signature = {:?}, gas = {}",
            //     signature,
            //     gstd::exec::gas_available()
            // );
            let public_keys: Vec<PublicKey> = public_keys
                .iter()
                .map(|key| {
                    PublicKey::from_uncompressed_bytes(key)
                        .expect("Can't deserialize PublicKey from Vec<u8>")
                })
                .collect();

            gstd::debug!("AZOYAN deserialized public_keys = {:?}", public_keys);
            let messages = &messages.iter().map(|v| &v[..]).collect::<Vec<_>>()[..];

            gstd::debug!("AZOYAN deserialized messages = {:?}", messages);
            let is_verified = signature::verify_messages(&signature, messages, &public_keys);

            match is_verified {
                true => Event::Verified,
                false => Event::NotVerified,
            }
        }
        Action::VerifyHashes(VerifyHashes {
            signature,
            hashes,
            public_keys,
        }) => {
            let signature = Signature::from_uncompressed_bytes(&signature).unwrap();
            let public_keys: Vec<PublicKey> = public_keys
                .iter()
                .map(|key| {
                    PublicKey::from_uncompressed_bytes(key)
                        .expect("Can't deserialize PublicKey from Vec<u8>")
                })
                .collect();
            gstd::debug!("AZOYAN deserialized public_keys = {:?}", public_keys);

            let hashes: Vec<G2Projective> = hashes.iter().map(|s| G2Projective::from(s)).collect();
            
            let is_verified = signature::verify_hashes(&signature, hashes, &public_keys);

            match is_verified {
                true => Event::Verified,
                false => Event::NotVerified,
            }
        }
    };
    // let result = Event::Verified;
    reply(result).expect("Failed to encode or reply with `Result<Event, Error>`");

    Ok(())
}

fn common_state() -> <ContractMetadata as Metadata>::State {
    let Contract {
        transactions,
        current_tid,
    } = static_mut_state();
    State {
        transactions: transactions.clone(),
        current_tid: *current_tid,
    }
}

#[no_mangle]
extern "C" fn meta_state() -> *const [i32; 2] {
    // let query = msg::load().expect("Failed to load or decode `StateQuery` from `meta_state()`");
    let state = common_state();

    let reply = state.encode();

    util::to_leak_ptr(reply.encode())
}

#[no_mangle]
extern "C" fn state() {
    reply(common_state()).expect(
        "Failed to encode or reply with `<ContractMetadata as Metadata>::State` from `state()`",
    );
}

#[no_mangle]
extern "C" fn metahash() {
    let metahash: [u8; 32] = include!("../.metahash");

    reply(metahash).expect("Failed to encode or reply with `[u8; 32]` from `metahash()`");
}

fn reply(payload: impl Encode) -> GstdResult<MessageId> {
    msg::reply(payload, 0)
}
