use hex::encode;
use chrono::DateTime;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, LowerHex, UpperHex, Debug},
    ops::Deref,
};

use thiserror::Error;
use web3::{
    signing::{hash_message, keccak256, recover, RecoveryError},
    types::{H160, H256},
};

/// An error that can occur when decoding a hexadecimal string
#[derive(Debug, PartialEq, Error)]
pub enum DecodeHexError {
    #[error("hexadecimal value must be prefixed with 0x")]
    MissingPrefix,

    #[error("odd number of digits")]
    OddLength,

    #[error("invalid string length")]
    InvalidLength,

    #[error("invalid character {c:?} at position {index}")]
    InvalidHexCharacter { c: char, index: usize },
}

/// Converts an `hex::FromHexError` into a DecodeHexError
impl From<hex::FromHexError> for DecodeHexError {
    fn from(err: hex::FromHexError) -> Self {
        match err {
            hex::FromHexError::OddLength => DecodeHexError::OddLength,
            hex::FromHexError::InvalidStringLength => DecodeHexError::InvalidLength,
            hex::FromHexError::InvalidHexCharacter { c, index } => {
                DecodeHexError::InvalidHexCharacter {
                    c,
                    index: index + 2,
                }
            }
        }
    }
}

impl From<secp256k1::Error> for DecodeHexError {
    fn from(_value: secp256k1::Error) -> Self {
        DecodeHexError::InvalidLength
    }
}

/// Decodes a hex string prefixed with `0x` into raw bytes.
///
/// Both, upper and lower case characters are valid in the input string and can
/// even be mixed (e.g. `0xf9b4ca`, `0xF9B4CA` and `0xf9B4Ca` are all valid strings).
///
/// # Example
///
/// ```
/// use dcl_crypto::account::{decode, DecodeHexError};
///
/// assert_eq!(
///     decode("0x48656c6c6f20776f726c6421"),
///     Ok("Hello world!".to_owned().into_bytes())
/// );
///
/// assert_eq!(decode("123"), Err(DecodeHexError::MissingPrefix));
/// assert_eq!(decode("0x123"), Err(DecodeHexError::OddLength));
/// assert_eq!(decode("0xfo"), Err(DecodeHexError::InvalidHexCharacter { c: 'o', index: 3 }));
/// ```
pub fn decode(value: &str) -> Result<Vec<u8>, DecodeHexError> {
    if !value.starts_with("0x") {
        return Err(DecodeHexError::MissingPrefix);
    }

    if value.len() % 2 != 0 {
        return Err(DecodeHexError::OddLength);
    }

    Ok(hex::decode(&value[2..])?)
}

/// Decode a hex string prefixed with `0x` into a mutable bytes slice.
///
/// Both, upper and lower case characters are valid in the input string and can
/// even be mixed (e.g. `0xf9b4ca`, `0xF9B4CA` and `0xf9B4Ca` are all valid strings).
///
/// # Example
///
/// ```
/// use dcl_crypto::account::{decode_to_slice, DecodeHexError};
///
/// let mut bytes = [0u8; 4];
/// assert_eq!(decode_to_slice("0x6b697769", &mut bytes as &mut [u8]), Ok(()));
/// assert_eq!(&bytes, b"kiwi");
/// ```
pub fn decode_to_slice(value: &str, bits: &mut [u8]) -> Result<(), DecodeHexError> {
    if !value.starts_with("0x") {
        return Err(DecodeHexError::MissingPrefix);
    }

    if value.len() != ((bits.len() * 2) + 2) {
        return Err(DecodeHexError::InvalidLength);
    }

    Ok(hex::decode_to_slice(&value[2..], bits)?)
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Address(H160);

impl Deref for Address {
    type Target = H160;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; 20]> for Address {
    /// Converts `[u8; 20]` into an `Address`
    ///
    /// ```rust
    ///   use dcl_crypto::account::Address;
    ///
    ///   let address = Address::from([0; 20]);
    ///   assert_eq!(address.to_string(), "0x0000000000000000000000000000000000000000")
    /// ```
    fn from(value: [u8; 20]) -> Self {
        Self(H160(value))
    }
}

impl From<H160> for Address {
    /// Converts an `H160` into an `Address`
    ///
    /// ```rust
    ///   use web3::types::H160;
    ///   use dcl_crypto::account::Address;
    ///
    ///   let address = Address::from(H160([0; 20]));
    ///   assert_eq!(address.to_string(), "0x0000000000000000000000000000000000000000")
    /// ```
    fn from(value: H160) -> Self {
        Self(value)
    }
}

impl std::cmp::PartialEq<H160> for Address {
    fn eq(&self, other: &H160) -> bool {
        self.0 == *other
    }
}

impl std::cmp::PartialEq<H160> for &Address {
    fn eq(&self, other: &H160) -> bool {
        self.0 == *other
    }
}

impl From<Address> for String {
    /// Formats an `Address` into its `String` representation
    fn from(value: Address) -> Self {
        value.checksum()
    }
}

impl TryFrom<&str> for Address {
    type Error = DecodeHexError;

    /// Converts an hexadecimal representation into an Address
    ///
    /// ```rust
    ///   use dcl_crypto::account::Address;
    ///
    ///   let lower_address = Address::try_from("0xf15fd08462c3248b2bfe9c39b48af7801fc303db");
    ///   let upper_address = Address::try_from("0xF15FD08462C3248B2BFE9C39B48AF7801FC303DB");
    ///   let address_expected: [u8; 20] = [ 241, 95, 208, 132, 98, 195, 36, 139, 43, 254, 156, 57, 180, 138, 247, 128, 31, 195, 3, 219];
    ///   assert_eq!(lower_address.unwrap(), Address::from(address_expected));
    ///   assert_eq!(upper_address.unwrap(), Address::from(address_expected));
    /// ```
    ///
    /// It requires the address string to be prefixed with `0x`
    /// ```rust
    ///   use dcl_crypto::account::{Address, DecodeHexError};
    ///
    ///   let not_prefixed_address = Address::try_from("f15fd08462c3248b2bfe9c39b48af7801fc303db");
    ///   assert_eq!(not_prefixed_address.is_err(), true);
    ///   assert_eq!(not_prefixed_address, Err(DecodeHexError::MissingPrefix));
    /// ```
    ///
    /// It requires the address to be `42` characters long
    /// ```rust
    ///   use dcl_crypto::account::{Address, DecodeHexError};
    ///
    ///   let len_41_address = Address::try_from("0xf15fd08462c3248b2bfe9c39b48af7801fc303d");
    ///   assert_eq!(len_41_address.is_err(), true);
    ///   assert_eq!(len_41_address, Err(DecodeHexError::InvalidLength));
    ///
    ///   let len_43_address = Address::try_from("0xf15fd08462c3248b2bfe9c39b48af7801fc303dbb");
    ///   assert_eq!(len_43_address.is_err(), true);
    ///   assert_eq!(len_43_address, Err(DecodeHexError::InvalidLength));
    /// ```
    ///
    /// It requires all characters to be hexadecimals
    /// ```rust
    ///   use dcl_crypto::account::{Address, DecodeHexError};
    ///
    ///   let not_hex_address = Address::try_from("0xf15fd08462c3248b2bfe9c39b48af7801fc303dx");
    ///   assert_eq!(not_hex_address.is_err(), true);
    ///   assert_eq!(not_hex_address, Err(DecodeHexError::InvalidHexCharacter{ c: 'x', index: 41}));
    /// ```
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut bits: [u8; 20] = [0; 20];
        match decode_to_slice(value, &mut bits) {
            Ok(_) => Ok(Self::from(bits)),
            Err(err) => Err(err),
        }
    }
}

impl TryFrom<String> for Address {
    type Error = DecodeHexError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl UpperHex for Address {
    /// Formats the `Address` into its hexadecimal uppercase representation
    ///
    /// ```rust
    ///     use dcl_crypto::account::Address;
    ///     let address = Address::from([255; 20]);
    ///     let zero = Address::from([0; 20]);
    ///
    ///     assert_eq!(format!("{zero:X}"), "0000000000000000000000000000000000000000");
    ///     assert_eq!(format!("{address:X}"), "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    ///
    ///     assert_eq!(format!("{zero:#X}"), "0X0000000000000000000000000000000000000000");
    ///     assert_eq!(format!("{address:#X}"), "0XFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::UpperHex::fmt(&**self, f)
    }
}

impl LowerHex for Address {
    /// Formats the `Address` into its hexadecimal lowercase representation
    ///
    /// ```rust
    ///     use dcl_crypto::account::Address;
    ///     let address = Address::from([255; 20]);
    ///     let zero = Address::from([0; 20]);
    ///
    ///     assert_eq!(format!("{zero:x}"), "0000000000000000000000000000000000000000");
    ///     assert_eq!(format!("{address:x}"), "ffffffffffffffffffffffffffffffffffffffff");
    ///
    ///     assert_eq!(format!("{zero:#x}"), "0x0000000000000000000000000000000000000000");
    ///     assert_eq!(format!("{address:#x}"), "0xffffffffffffffffffffffffffffffffffffffff");
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&**self, f)
    }
}

impl Display for Address {
    /// Format an Address into it string representation
    ///
    /// ```rust
    ///   use dcl_crypto::account::Address;
    ///   assert_eq!(Address::from([0; 20]).to_string(), "0x0000000000000000000000000000000000000000");
    ///   assert_eq!(Address::from([255; 20]).to_string(), "0xffffffffffffffffffffffffffffffffffffffff");
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:#x}")
    }
}

impl Address {
    /// Creates an instance of the zero address
    ///
    /// ```rust
    ///   use dcl_crypto::account::Address;
    ///   assert_eq!(Address::zero().to_string(), "0x0000000000000000000000000000000000000000")
    /// ```
    pub fn zero() -> Self {
        Self::from([0; 20])
    }

    /// Calculate ERC-55 version of the address
    ///
    /// ```rust
    ///     use dcl_crypto::account::Address;
    ///     assert_eq!(Address::try_from("0x0f5d2fb29fb7d3cfee444a200298f468908cc942").unwrap().checksum(), "0x0F5D2fB29fb7d3CFeE444a200298f468908cC942");
    ///     assert_eq!(Address::try_from("0x554bb6488ba955377359bed16b84ed0822679cdc").unwrap().checksum(), "0x554BB6488bA955377359bED16b84Ed0822679CDC");
    ///     assert_eq!(Address::try_from("0x1784ef41af86e97f8d28afe95b573a24aeda966e").unwrap().checksum(), "0x1784Ef41af86e97f8D28aFe95b573a24aEDa966e");
    ///     assert_eq!(Address::from([255; 20]).checksum(), "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF");
    ///     assert_eq!(Address::from([0; 20]).checksum(), "0x0000000000000000000000000000000000000000");
    /// ```
    pub fn checksum(&self) -> String {
        let hash = keccak256(format!("{self:x}").as_bytes());
        let checksum = self
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, b)| {
                // let h = hash[i];
                let h1 = (hash[i] & 0b1111_0000) >> 4;
                let h2 = hash[i] & 0b0000_1111;
                let hex = format!("{b:02x}");
                let b1 = hex.get(0..=0).unwrap_or("0");
                let b2 = hex.get(1..=1).unwrap_or("0");
                // hex
                format!(
                    "{}{}",
                    if h1 >= 8 {
                        b1.to_uppercase()
                    } else {
                        b1.to_lowercase()
                    },
                    if h2 >= 8 {
                        b2.to_uppercase()
                    } else {
                        b2.to_lowercase()
                    },
                )
            })
            .collect::<String>();

        format!("0x{checksum}")
    }
}

pub const PERSONAL_SIGNATURE_SIZE: usize = 65;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(try_from = "String", into = "String")]
pub struct PersonalSignature([u8; PERSONAL_SIGNATURE_SIZE]);

impl Deref for PersonalSignature {
    type Target = [u8; PERSONAL_SIGNATURE_SIZE];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for PersonalSignature {
    fn default() -> Self {
        PersonalSignature([0; PERSONAL_SIGNATURE_SIZE])
    }
}

impl From<[u8; PERSONAL_SIGNATURE_SIZE]> for PersonalSignature {
    fn from(value: [u8; PERSONAL_SIGNATURE_SIZE]) -> Self {
        Self(value)
    }
}

impl From<web3::signing::Signature> for PersonalSignature {
    fn from(value: web3::signing::Signature) -> Self {
        let mut bits = [0u8; PERSONAL_SIGNATURE_SIZE];
        bits[..32].copy_from_slice(&value.r.0);
        bits[32..64].copy_from_slice(&value.s.0);
        bits[64] = (value.v * 0b1111) as u8;
        Self(bits)
    }
}

impl From<secp256k1::ecdsa::Signature> for PersonalSignature {
    fn from(value: secp256k1::ecdsa::Signature) -> Self {
        let mut bits: [u8; 65] = [0; 65];
        bits[..64].copy_from_slice(&value.serialize_compact());
        bits[64] = 0x1b;
        Self(bits)
    }
}

impl TryFrom<&str> for PersonalSignature {
    type Error = DecodeHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 132 {
            return Err(DecodeHexError::InvalidLength);
        }

        let mut bits = [0u8; PERSONAL_SIGNATURE_SIZE];
        match decode_to_slice(value, &mut bits) {
            Ok(_) => Ok(Self::from(bits)),
            Err(err) => Err(err),
        }
    }
}

impl TryFrom<String> for PersonalSignature {
    type Error = DecodeHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl From<PersonalSignature> for String {
    fn from(value: PersonalSignature) -> Self {
        value.to_string()
    }
}

impl From<PersonalSignature> for web3::signing::Signature {
    fn from(value: PersonalSignature) -> Self {
        let mut r: [u8; 32] = [0; 32];
        r.copy_from_slice(&value[..32]);

        let mut s: [u8; 32] = [0; 32];
        s.copy_from_slice(&value[32..64]);

        let v: u64 = value.0[64] as u64;

        Self {
            v,
            r: H256(r),
            s: H256(s),
        }
    }
}

impl From<PersonalSignature> for Vec<u8> {
    fn from(value: PersonalSignature) -> Self {
        value.to_vec()
    }
}

impl Display for PersonalSignature {
    /// Format signature on its hexadecimal representation
    ///
    /// ```rust
    ///   use dcl_crypto::account::PersonalSignature;
    ///   assert_eq!(PersonalSignature::from([0; 65]).to_string(), "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl PersonalSignature {
    /// Recover the signer of the signature from a giving message
    ///
    /// ```rust
    ///   use dcl_crypto::account::PersonalSignature;
    ///   let signer = "0xb92702b3eefb3c2049aeb845b0335b283e11e9c6";
    ///   let message = "Decentraland Login\nEphemeral address: 0xA69ef8104E05325B01A15bA822Be43eF13a2f5d3\nExpiration: 2023-03-30T15:44:55.787Z";
    ///   let payload = "0xd35f95b1e35e95e31a65d972348633c34411030ce971e2c49513a28a04706aa44906c6da35cf7bad51872b15dc971541952be62e63af8c8e9b300dfcddf4c60a1c";
    ///
    ///   let sign = PersonalSignature::try_from(payload).unwrap();
    ///   let address = sign.try_recover_from_message(message).unwrap();
    ///   assert_eq!(address.to_string(), signer)
    /// ```
    pub fn try_recover_from_message(&self, message: &str) -> Result<Address, RecoveryError> {
        let result = recover(
            hash_message(message).as_bytes(),
            &self.0[..=63],
            (self.0[64] as i32) - 27,
        );

        match result {
            Ok(h160) => Ok(Address::from(h160)),
            Err(err) => Err(err),
        }
    }

    pub fn is_valid_signature(&self, message: &str, signer: &Address) -> bool {
        self.try_recover_from_message(message)
            .map(|address| address == *signer)
            .unwrap_or(false)
    }
}

/// And
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(try_from = "String", into = "String")]
pub struct EIP1271Signature(Vec<u8>);

impl Deref for EIP1271Signature {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for EIP1271Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

impl TryFrom<&str> for EIP1271Signature {
    type Error = DecodeHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let data = decode(value)?;
        Ok(Self(data))
    }
}

impl TryFrom<String> for EIP1271Signature {
    type Error = DecodeHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl From<EIP1271Signature> for Vec<u8> {
    fn from(value: EIP1271Signature) -> Self {
        value.to_vec()
    }
}

impl From<EIP1271Signature> for String {
    fn from(value: EIP1271Signature) -> Self {
        format!("0x{}", hex::encode(value.0))
    }
}

/// Alias of EIP1271Signature
/// See <https://eips.ethereum.org/EIPS/eip-1271>
/// See <https://github.com/ethereum/EIPs/issues/1654>
pub type EIP1654Signature = EIP1271Signature;

static DEFAULT_EPHEMERAL_PAYLOAD_TITLE: &str = "Decentraland Login";

/// An `EphemeralPayload` is a message that delegates the right to sign a message to a specific address until an expiration date.
///
/// ```rust
///     use dcl_crypto::account::{Address, EphemeralPayload};
///
///     let payload = EphemeralPayload::try_from("Decentraland Login\nEphemeral address: 0xA69ef8104E05325B01A15bA822Be43eF13a2f5d3\nExpiration: 2023-03-30T15:44:55.787Z").unwrap();
///     let expiration = chrono::DateTime::parse_from_rfc3339("2023-03-30T15:44:55.787Z").unwrap().with_timezone(&chrono::Utc);
///
///     assert_eq!(payload, EphemeralPayload::new(
///         Address::try_from("0xA69ef8104E05325B01A15bA822Be43eF13a2f5d3").unwrap(),
///         expiration,
///     ))
/// ```
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(try_from = "String", into = "String")]
pub struct EphemeralPayload {
    pub title: String,
    pub address: Address,
    pub expiration: chrono::DateTime<chrono::Utc>,
}

#[derive(PartialEq, Debug, Error)]
pub enum EphemeralPayloadError {
    #[error("invalid payload content")]
    InvalidPayload,

    #[error("missing title line on payload")]
    MissingTitle,

    #[error("missing address line on payload")]
    MissingAddress,

    #[error("invalid address: {err} (address: {value})")]
    InvalidAddress { err: DecodeHexError, value: String },

    #[error("missing expiration line on payload")]
    MissingExpiration,

    #[error("invalid expiration: {err} (expiration: {value})")]
    InvalidExpiration {
        err: chrono::ParseError,
        value: String,
    },
}

static RE_TITLE_CAPTURE: &str = "title";
static RE_ADDRESS_CAPTURE: &str = "address";
static RE_EXPIRATION_CAPTURE: &str = "expiration";

impl TryFrom<&str> for EphemeralPayload {
    type Error = EphemeralPayloadError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        lazy_static! {
            static ref EPHEMERAL_PAYLOAD_REGEX: Regex = Regex::new(&format!(
                r"^(?P<{}>[^\r\n]*)\r?\nEphemeral address: (?P<{}>[^\r\n]*)\r?\nExpiration: (?P<{}>.*)$",
                RE_TITLE_CAPTURE, RE_ADDRESS_CAPTURE, RE_EXPIRATION_CAPTURE
            ))
            .unwrap();
        }

        let captures = match EPHEMERAL_PAYLOAD_REGEX.captures(value) {
            None => return Err(EphemeralPayloadError::InvalidPayload),
            Some(captures) => captures,
        };

        let title = match captures.name(RE_TITLE_CAPTURE) {
            None => return Err(EphemeralPayloadError::MissingTitle),
            Some(title) => title.as_str().to_string(),
        };

        let address = match captures.name(RE_ADDRESS_CAPTURE) {
            None => return Err(EphemeralPayloadError::MissingAddress),
            Some(address) => {
                let value = address.as_str();
                Address::try_from(value).map_err(|err| EphemeralPayloadError::InvalidAddress {
                    value: value.to_string(),
                    err,
                })?
            }
        };

        let expiration = match captures.name(RE_EXPIRATION_CAPTURE) {
            None => return Err(EphemeralPayloadError::MissingExpiration),
            Some(expiration) => {
                let value = expiration.as_str();
                DateTime::parse_from_rfc3339(value)
                    .map_err(|err| EphemeralPayloadError::InvalidExpiration {
                        value: value.to_string(),
                        err,
                    })?
                    .with_timezone(&chrono::Utc)
            }
        };

        Ok(Self {
            title,
            address,
            expiration,
        })
    }
}

impl TryFrom<String> for EphemeralPayload {
    type Error = EphemeralPayloadError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl Display for EphemeralPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\nEphemeral address: {}\nExpiration: {}",
            self.title,
            self.address.checksum(),
            self.expiration
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        )
    }
}

impl From<EphemeralPayload> for String {
    fn from(payload: EphemeralPayload) -> Self {
        format!("{}", payload)
    }
}

impl EphemeralPayload {
    pub fn new(address: Address, expiration: chrono::DateTime<chrono::Utc>) -> Self {
        Self::new_with_title(
            String::from(DEFAULT_EPHEMERAL_PAYLOAD_TITLE),
            address,
            expiration,
        )
    }

    pub fn new_with_title(
        title: String,
        address: Address,
        expiration: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            title,
            address,
            expiration,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expiration < chrono::Utc::now()
    }

    pub fn is_expired_at(&self, time: &chrono::DateTime<chrono::Utc>) -> bool {
        self.expiration < *time
    }
}

// abstraction to implement secp256k1::ThirtyTwoByteHash for H256
struct Hash(H256);

impl secp256k1::ThirtyTwoByteHash for Hash {
    fn into_32(self) -> [u8; 32] {
        self.0.0
    }
}

// Calculate the public key from a secret key
fn to_public_key(secret: &secp256k1::SecretKey) -> secp256k1::PublicKey {
    lazy_static!{
        static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    }

    secret.public_key(&SECP256K1)
}

// Intermediary representation of a private key from an Identity
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EphemeralAccount {
    address: String,
    public_key: String,
    pub private_key: Account,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EphemeralAccount", into = "EphemeralAccount")]
pub struct Account(secp256k1::SecretKey);

impl TryFrom<&str> for Account {
    type Error = DecodeHexError;

    /// Creates a new account from a private key in hex format.
    ///
    /// ```rust
    /// use dcl_crypto::account::Account;
    ///
    /// ```
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];
        decode_to_slice(value, &mut bytes)?;
        let key = secp256k1::SecretKey::from_slice(&bytes)?;
        Ok(Self(key))
    }
}

impl TryFrom<String> for Account {
    type Error = DecodeHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl From<Account> for String {
    fn from(account: Account) -> Self {
        format!("0x{}", encode(account.0.secret_bytes()))
    }
}

impl From<EphemeralAccount> for Account {
    fn from(account: EphemeralAccount) -> Self {
        account.private_key
    }
}

impl From<Account> for EphemeralAccount {
    fn from(account: Account) -> Self {
        let public = to_public_key(&account.0).serialize_uncompressed();
        Self {
            address: account.address().checksum(),
            public_key: format!("0x{}", hex::encode(public)),
            private_key: account,
        }
    }
}

impl Account {

    /// Return the address of the account.
    ///
    /// ```rust
    /// use dcl_crypto::account::{Account, Address};
    ///
    /// let account = Account::try_from("0xbc453a92d9baeb3d10294cbc1d48ef6738f718fd31b4eb8085efe7b311299399").unwrap();
    /// assert_eq!(account.address(), Address::try_from("0x84452bbFA4ca14B7828e2F3BBd106A2bD495CD34").unwrap());
    /// ```
    pub fn address(&self) -> Address {
        let public = to_public_key(&self.0).serialize_uncompressed();
        let hash = keccak256(&public[1..]);
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash[12..]);
        Address::from(bytes)
    }

    /// Sign a message with the account.
    ///
    /// ```rust
    /// use dcl_crypto::account::{Account, PersonalSignature};
    ///
    /// let account = Account::try_from("0xbc453a92d9baeb3d10294cbc1d48ef6738f718fd31b4eb8085efe7b311299399").unwrap();
    /// let message = account.sign("signed message");
    /// assert_eq!(message, PersonalSignature::try_from("0x013e0b0b75bd8404d70a37d96bb893596814d8f29f517e383d9d1421111f83c32d4ca0d6e399349c7badd54261feaa39895d027880d28d806c01089677400b7c1b").unwrap());
    /// ```
    pub fn sign(&self, message: &str) -> PersonalSignature {
        let data = hash_message(message.as_bytes());
        let message = secp256k1::Message::from(Hash(data));
        let bytes = self.0.sign_ecdsa(message);
        bytes.into()
    }
}
