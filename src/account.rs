use lazy_static::lazy_static;
use regex::Regex;
use std::{fmt::{Display, UpperHex, LowerHex}, ops::Deref};
use chrono::DateTime;
use serde::{Serialize, Deserialize};

use thiserror::Error;
use web3::{
    signing::{hash_message, recover, RecoveryError, keccak256},
    types::{H256, H160},
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
                DecodeHexError::InvalidHexCharacter { c, index: index + 2 }
            }
        }
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
/// use decentraland_crypto::account::{decode, DecodeHexError};
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
/// use decentraland_crypto::account::{decode_to_slice, DecodeHexError};
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
    ///   use decentraland_crypto::account::Address;
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
    ///   use decentraland_crypto::account::Address;
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
        value.to_string_checksum()
    }
}

impl TryFrom<&str> for Address {
    type Error = DecodeHexError;

    /// Converts an hexadecimal representation into an Address
    ///
    /// ```rust
    ///   use decentraland_crypto::account::Address;
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
    ///   use decentraland_crypto::account::{Address, DecodeHexError};
    ///
    ///   let not_prefixed_address = Address::try_from("f15fd08462c3248b2bfe9c39b48af7801fc303db");
    ///   assert_eq!(not_prefixed_address.is_err(), true);
    ///   assert_eq!(not_prefixed_address, Err(DecodeHexError::MissingPrefix));
    /// ```
    ///
    /// It requires the address to be `42` characters long
    /// ```rust
    ///   use decentraland_crypto::account::{Address, DecodeHexError};
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
    ///   use decentraland_crypto::account::{Address, DecodeHexError};
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
    ///     use decentraland_crypto::account::Address;
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
    ///     use decentraland_crypto::account::Address;
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
    ///   use decentraland_crypto::account::Address;
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
    ///   use decentraland_crypto::account::Address;
    ///   assert_eq!(Address::zero().to_string(), "0x0000000000000000000000000000000000000000")
    /// ```
    pub fn zero() -> Self {
        Self::from([0; 20])
    }

    /// Calculate ERC-55 version of the address
    ///
    /// ```rust
    ///     use decentraland_crypto::account::Address;
    ///     assert_eq!(Address::try_from("0x0f5d2fb29fb7d3cfee444a200298f468908cc942").unwrap().to_string_checksum(), "0x0F5D2fB29fb7d3CFeE444a200298f468908cC942");
    ///     assert_eq!(Address::try_from("0x554bb6488ba955377359bed16b84ed0822679cdc").unwrap().to_string_checksum(), "0x554BB6488bA955377359bED16b84Ed0822679CDC");
    ///     assert_eq!(Address::try_from("0x1784ef41af86e97f8d28afe95b573a24aeda966e").unwrap().to_string_checksum(), "0x1784Ef41af86e97f8D28aFe95b573a24aEDa966e");
    ///     assert_eq!(Address::from([255; 20]).to_string_checksum(), "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF");
    ///     assert_eq!(Address::from([0; 20]).to_string_checksum(), "0x0000000000000000000000000000000000000000");
    /// ```
    pub fn to_string_checksum(&self) -> String {
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(try_from = "String", into = "String")]
pub struct PersonalSignature([u8; 65]);

impl Deref for PersonalSignature {
    type Target = [u8; 65];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for PersonalSignature {
    fn default() -> Self {
        PersonalSignature([0; 65])
    }
}

impl From<[u8; 65]> for PersonalSignature {
    fn from(value: [u8; 65]) -> Self {
        Self(value)
    }
}

impl From<web3::signing::Signature> for PersonalSignature {
    fn from(value: web3::signing::Signature) -> Self {
        let mut bits: [u8; 65] = [0; 65];
        bits[..32].copy_from_slice(&value.r.0);
        bits[32..64].copy_from_slice(&value.s.0);
        bits[64] = (value.v * 0b1111) as u8;
        Self(bits)
    }
}

impl TryFrom<&str> for PersonalSignature {
    type Error = DecodeHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 132 {
            return Err(DecodeHexError::InvalidLength);
        }

        let mut bits: [u8; 65] = [0; 65];
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

    Self { v, r: H256(r), s: H256(s) }
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
    ///   use decentraland_crypto::account::PersonalSignature;
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
    ///   use decentraland_crypto::account::PersonalSignature;
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
/// See https://eips.ethereum.org/EIPS/eip-1271
/// See https://github.com/ethereum/EIPs/issues/1654
pub type EIP1654Signature = EIP1271Signature;


static DEFAULT_EPHEMERAL_PAYLOAD_TITLE: &str = "Decentraland Login";

/// An `EphemeralPayload` is a message that delegates the right to sign a message to a specific address until an expiration date.
///
/// ```rust
///     use decentraland_crypto::account::{Address, EphemeralPayload};
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
    pub raw: String,
    pub title: String,
    pub address: Address,
    pub expiration: chrono::DateTime<chrono::Utc>,
}

#[derive(PartialEq, Debug, Error)]
pub enum DelegationPayloadError {
    #[error("invalid payload content")]
    InvalidPayload,

    #[error("missing title line on payload")]
    MissingTitle,

    #[error("missing address line on payload")]
    MissingAddress,

    #[error("invalid address: {0}")]
    InvalidAddress(DecodeHexError),

    #[error("missing expiration line on payload")]
    MissingExpiration,

    #[error("invalid expiration: {0}")]
    InvalidExpiration(chrono::ParseError),
}

impl From<DecodeHexError> for DelegationPayloadError {
    fn from(err: DecodeHexError) -> Self {
        DelegationPayloadError::InvalidAddress(err)
    }
}

impl From<chrono::ParseError> for DelegationPayloadError {
    fn from(err: chrono::ParseError) -> Self {
        DelegationPayloadError::InvalidExpiration(err)
    }
}

static RE_TITLE_CAPTURE: &str = "title";
static RE_ADDRESS_CAPTURE: &str = "address";
static RE_EXPIRATION_CAPTURE: &str = "expiration";

impl TryFrom<&str> for EphemeralPayload {
    type Error = DelegationPayloadError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        lazy_static! {
            static ref EPHEMERAL_PAYLOAD_REGEX: Regex = Regex::new(&format!(
                r"^(?P<{}>.*)\nEphemeral address: (?P<{}>.*)\nExpiration: (?P<{}>.*)$",
                RE_TITLE_CAPTURE, RE_ADDRESS_CAPTURE, RE_EXPIRATION_CAPTURE
            ))
            .unwrap();
        }

        let captures = match EPHEMERAL_PAYLOAD_REGEX.captures(value) {
            None => return Err(DelegationPayloadError::InvalidPayload),
            Some(captures) => captures,
        };

        let title = match captures.name(RE_TITLE_CAPTURE) {
            None => return Err(DelegationPayloadError::MissingTitle),
            Some(title) => title.as_str().to_string(),
        };

        let address = match captures.name(RE_ADDRESS_CAPTURE) {
            None => return Err(DelegationPayloadError::MissingAddress),
            Some(address) => Address::try_from(address.as_str())?,
        };

        let expiration = match captures.name(RE_EXPIRATION_CAPTURE) {
            None => return Err(DelegationPayloadError::MissingExpiration),
            Some(expiration) => {
                DateTime::parse_from_rfc3339(expiration.as_str())?.with_timezone(&chrono::Utc)
            }
        };

        Ok(Self {
            raw: value.to_string(),
            title,
            address,
            expiration,
        })
    }
}

impl TryFrom<String> for EphemeralPayload {
    type Error = DelegationPayloadError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl Display for EphemeralPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.raw
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
        Self::new_with_title(String::from(DEFAULT_EPHEMERAL_PAYLOAD_TITLE), address, expiration)
    }

    pub fn new_with_title(
        title: String,
        address: Address,
        expiration: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let raw = format!(
            "{}\nEphemeral address: {}\nExpiration: {}",
            title,
            address.to_string_checksum(),
            expiration
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        );

        Self {
            raw,
            title,
            address,
            expiration,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expiration < chrono::Utc::now()
    }

    pub fn is_expired_at(&self, time: chrono::DateTime<chrono::Utc>) -> bool {
        self.expiration < time
    }
}