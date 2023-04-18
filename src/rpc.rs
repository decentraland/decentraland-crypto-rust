use ethabi::{Contract, Token};
use thiserror::Error;
use web3::{
    api::Eth,
    signing::keccak256,
    types::{Bytes, CallRequest}, Transport
};

use crate::account::Address;

static MAGIC_EIP1271_VALUE: [u8; 4] = [22, 38, 186, 126];
static EIP1654_ABI: &[u8] = include_bytes!("../contracts/SignatureValidator.json");

#[derive(Error, Debug)]
pub enum RPCCallError {

    #[error("rpc resolver not implemented")]
    NotImplemented,

    #[error("error encoding params: {0}")]
    Encode(ethabi::Error),

    #[error("error calling rpc: {0}")]
    Call(web3::Error),

    #[error("error decoding result: {0}")]
    Decode(ethabi::Error),
}

/// A signature validator that receives an address, a message and a signature and validates it using local resources.
/// ```
/// use ethabi::Contract;
/// use web3::{Web3, transports::Http};
/// use dcl_crypto::rpc::rpc_call_is_valid_signature;
/// use dcl_crypto::account::{Address, EIP1271Signature};
///
/// # tokio_test::block_on(async {
///     let endpoint = env!("ETHEREUM_MAINNET_RPC");
///     let transport = Http::new(endpoint).unwrap();
///     let eth = Web3::new(transport).eth();
///     let address = Address::try_from("0x3b21028719a4aca7ebee35b0157a6f1b0cf0d0c5").unwrap();
///     // let address = Address::try_from("0xbdbee960fb7ce6267c467665dea046d0a4849cda").unwrap();
///     let message = "Decentraland Login\nEphemeral address: 0x69fBdE5Da06eb76e8E7F6Fd2FEEd968F28b951a5\nExpiration: Tue Aug 06 7112 10:14:51 GMT-0300 (Argentina Standard Time)".to_string();
///     let hash = EIP1271Signature::try_from("0x03524dbe44d19aacc8162b4d5d17820c370872de7bfd25d1add2b842adb1de546b454fc973b6d215883c30f4c21774ae71683869317d773f27e6bfaa9a2a05101b36946c3444914bb93f17a29d88e2449bcafdb6478b4835102c522197fa6f63d13ce5ab1d5c11c95db0c210fb4380995dff672392e5569c86d7c6bb2a44c53a151c").unwrap().to_vec();
///
///     let result = rpc_call_is_valid_signature(&eth, address, message, hash).await.unwrap();
///     assert_eq!(result, true);
/// # })
/// ```
pub async fn rpc_call_is_valid_signature<T: Transport>(
    eth: &Eth<T>,
    address: Address,
    message: String,
    hash: Vec<u8>,
) -> Result<bool, RPCCallError> {
    let contract = Contract::load(EIP1654_ABI).map_err(RPCCallError::Encode)?;
    let func = contract.function("isValidSignature")
        .map_err(RPCCallError::Encode)?;

    let call = func.encode_input(&[
        Token::FixedBytes(keccak256(message.as_bytes()).to_vec()),
        Token::Bytes(hash),
    ]).map_err(RPCCallError::Encode)?;

    let bytes = eth
        .call(
            CallRequest {
                from: None,
                to: Some(*address),
                gas: None,
                gas_price: None,
                value: None,
                data: Some(Bytes(call)),
                transaction_type: None,
                access_list: None,
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
            },
            None,
        )
        .await
        .map_err(RPCCallError::Call)?;

    let output = func.decode_output(&bytes.0)
        .map_err(RPCCallError::Decode)?;

    if let Some(token) = output.first() {
        if let Some(value) = token.clone().into_fixed_bytes() {
            return Ok(value == MAGIC_EIP1271_VALUE);
        }
    }

    Ok(false)
}
