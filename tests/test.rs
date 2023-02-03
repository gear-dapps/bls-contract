use app_io::*;
use gstd::Encode;
use gtest::{Program, System};
mod utils;
use crate::utils::prepare_test_data;

#[test]
fn test() {
    let system = System::new();

    system.init_logger();

    let program = Program::current(&system);
    let mut result = program.send_bytes(2, []);

    assert!(!result.main_failed());

    let (aggregated_signature, signed_messages, public_keys) =
        prepare_test_data(vec!["test1", "test2", "test3"]);

    result = program.send(
        2,
        Action::Verify(Verify {
            signature: aggregated_signature,
            messages: signed_messages,
            public_keys,
        }),
    );

    assert!(result.contains(&(2, Event::Verified.encode())));
    assert!(!result.contains(&(2, Event::NotVerified.encode())));
}
