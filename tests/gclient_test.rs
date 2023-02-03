// use bls::WASM_BINARY_OPT as WASM;
// use app_io::*;
// use gclient::{EventProcessor, GearApi, Result};
// use gstd::prelude::*;
// mod utils;
// use crate::utils::prepare_test_data;

// #[tokio::test]
// #[ignore]
// async fn gclient_test() -> Result<()> {
//     let client = GearApi::dev()
//         .await
//         .expect("The node must be running for a gclient test");
//     let mut listener = client.subscribe().await?;

//     let mut gas_limit = client
//         .calculate_upload_gas(None, WASM.into(), vec![], 0, true)
//         .await?
//         .min_limit;
//     let (mut message_id, program_id, _) = client
//         .upload_program_bytes(
//             WASM,
//             gclient::now_in_micros().to_le_bytes(),
//             [],
//             gas_limit,
//             0,
//         )
//         .await?;

//     assert!(listener.message_processed(message_id).await?.succeed());

//     let (aggregated_signature, signed_messages, public_keys) =
//         prepare_test_data(vec!["test1", "test2", "test3"]);

//     let verify = Verify {
//         signature: aggregated_signature,
//         messages: signed_messages,
//         public_keys,
//     };
//     let action = Action::Verify(verify);

//     gas_limit = client
//         .calculate_handle_gas(None, program_id, action.encode(), 0, true)
//         .await?
//         .min_limit;
//     (message_id, _) = client
//         .send_message(program_id, action, gas_limit, 0)
//         .await?;

//     let (_, raw_reply, _) = listener.reply_bytes_on(message_id).await?;

//     assert_eq!(
//         Event::Verified,
//         Decode::decode(
//             &mut raw_reply
//                 .expect("Received an error message instead of a reply")
//                 .as_slice()
//         )?
//     );

//     Ok(())
// }
