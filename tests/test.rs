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

    let (aggregated_signature, signed_messages, public_keys) = prepare_test_data(vec!["test1"]);

    println!("{:?}", aggregated_signature); // [16, 172, 135, 30, 59, 48, 128, 161, 203, 206, 197, 150, 232, 163, 226, 220, 183, 238, 91, 190, 171, 179, 191, 196, 223, 172, 137, 88, 48, 36, 203, 77, 129, 212, 44, 69, 251, 68, 195, 102, 40, 87, 24, 160, 30, 58, 77, 238, 8, 230, 84, 168, 14, 144, 172, 210, 89, 98, 160, 20, 19, 226, 136, 244, 196, 239, 61, 241, 10, 138, 232, 135, 136, 101, 155, 188, 85, 1, 161, 166, 192, 69, 119, 169, 220, 90, 139, 211, 218, 243, 147, 144, 170, 100, 30, 74, 6, 20, 184, 10, 159, 122, 86, 134, 196, 240, 134, 9, 110, 97, 82, 250, 181, 202, 120, 161, 178, 101, 250, 170, 65, 51, 22, 64, 130, 228, 43, 74, 112, 166, 246, 250, 187, 87, 104, 184, 159, 102, 71, 89, 219, 175, 14, 85, 23, 149, 145, 254, 3, 206, 94, 218, 22, 152, 90, 107, 200, 24, 1, 204, 250, 86, 69, 140, 152, 170, 101, 228, 44, 72, 240, 240, 75, 75, 192, 123, 140, 23, 175, 126, 249, 182, 114, 76, 213, 49, 34, 7, 3, 127, 230, 238]
    println!("{:?}", signed_messages); // [[116, 101, 115, 116, 49]]
    println!("{:?}", public_keys); // [[9, 0, 44, 62, 31, 239, 12, 60, 199, 175, 135, 74, 132, 27, 53, 143, 132, 177, 41, 195, 109, 14, 234, 34, 102, 20, 13, 171, 121, 146, 192, 230, 43, 184, 137, 205, 104, 248, 85, 250, 48, 99, 48, 71, 180, 33, 56, 105, 5, 21, 139, 113, 242, 43, 216, 18, 4, 122, 40, 227, 196, 153, 34, 224, 110, 29, 92, 174, 133, 146, 92, 205, 59, 243, 157, 185, 55, 222, 22, 101, 36, 68, 83, 174, 233, 44, 229, 42, 219, 71, 254, 81, 201, 81, 84, 100]]

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
