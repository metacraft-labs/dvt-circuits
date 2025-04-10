// #[macro_export]
// macro_rules! impl_hex_convertible {
//     ($name:ident, $size:expr) => {
//         impl HexConvertable for $name {
//             fn from_hex(hex: &str) -> Self {
//                 let bytes: [u8; $size] = hex::decode(hex).unwrap().try_into().unwrap();
//                 Self(bytes)
//             }

//             fn to_hex(&self) -> String {
//                 hex::encode(&self.0)
//             }
//         }
//     };
// }