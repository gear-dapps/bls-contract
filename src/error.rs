#[derive(Debug)]
pub enum Error {
    SizeMismatch,

    GroupDecode,

    CurveDecode,

    FieldDecode,

    InvalidPrivateKey,

    ZeroSizedInput,
}
