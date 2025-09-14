//! Fetch certificate of canister info and verify it.
//!
//! The public interface of Internet Computer (IC) offers a `read_state` API to query canister state.
//! Its return result is a time-stamped certificate that can be verified against the public key of the IC.
//! This is a powerful way of keeping a verifiable record of canister meta data such as module hash and controller list.
//!
//! This tool provides two commands:
//!
//! 1. `fetch canister_id`: call `read_state` on the given canister and print the result.
//!    The certificate is kept in its original CBOR encoding, represented as a hex-encoded string in JSON.
//!
//! 2. `verify`: read the result of `fetch` from standard input, verify its authenticity using IC's
//!    public key and print its info including module hash, controller list, and timestamp.
use candid::Principal;
use clap::*;
use ic_agent::{
    agent::{Agent, AgentError},
    hash_tree::Label,
    lookup_value, Certificate,
};
use serde::{Deserialize, Serialize};
use serde_bytes_repr::{ByteFmtDeserializer, ByteFmtSerializer};
use serde_json::{Deserializer, Serializer};
use std::io::{stdin, Read};

const URL: &str = "https://ic0.app";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Number of times to greet
    #[clap(long, default_value = "https://ic0.app")]
    url: String,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Fetch canister info
    Fetch { canister: String },
    /// Verify canister info
    Verify,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanisterInfo {
    pub canister_id: Principal,
    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

fn from_str<'a, T: Deserialize<'a>>(json: &'a str) -> Result<T, serde_json::Error> {
    let mut json_de = Deserializer::from_str(json);
    let bytefmt_json_de = ByteFmtDeserializer::new_hex(&mut json_de);
    T::deserialize(bytefmt_json_de)
}

fn to_string<T: Serialize>(msg: &T) -> String {
    let mut out = vec![];
    let mut ser = Serializer::new(&mut out);
    let ser = ByteFmtSerializer::hex(&mut ser);
    msg.serialize(ser).expect("Failed to serialize to JSON");
    String::from_utf8(out).expect("UTF8 conversion error")
}

pub async fn canister_info(
    agent: &Agent,
    canister_id: Principal,
) -> Result<CanisterInfo, AgentError> {
    let paths: Vec<Vec<Label<Vec<u8>>>> = vec![
        vec![
            "canister".into(),
            canister_id.as_slice().into(),
            "module_hash".into(),
        ],
        vec![
            "canister".into(),
            canister_id.as_slice().into(),
            "controllers".into(),
        ],
    ];

    let cert = agent.read_state_raw(paths, canister_id).await?;
    let mut certificate = vec![];
    ciborium::into_writer(&cert, &mut certificate).unwrap();
    Ok(CanisterInfo {
        canister_id,
        certificate,
    })
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicInfo {
    canister_id: Principal,
    #[serde(with = "serde_bytes")]
    module_hash: Vec<u8>,
    controllers: Vec<Principal>,
    time: u64,
}

fn verify_info(
    agent: &Agent,
    info: &CanisterInfo,
) -> Result<PublicInfo, Box<dyn std::error::Error>> {
    use ic_certificate_verification::VerifyCertificate;
    use serde_cbor::Value;

    let canister_id = info.canister_id;
    // CBOR compatibility hack: omit the delegation when it is null.
    let mut value: Value = serde_cbor::from_slice(&info.certificate)?;
    match &mut value {
        Value::Map(map) => {
            let key = Value::Text("delegation".to_string());
            match map.get(&key) {
                Some(Value::Null) => {
                    map.remove(&key);
                }
                _ => (),
            }
        }
        _ => (),
    }
    let cert: Certificate = serde_cbor::from_slice(&serde_cbor::to_vec(&value)? as &[u8])?;
    let mut time = lookup_value(&cert, vec!["time".as_ref()])?;
    let time = leb128::read::unsigned(&mut time)?;
    let module_hash = lookup_value(
        &cert,
        vec![
            "canister".as_ref(),
            canister_id.as_slice(),
            "module_hash".as_ref(),
        ],
    )?
    .to_vec();
    let controllers = lookup_value(
        &cert,
        vec![
            "canister".as_ref(),
            canister_id.as_slice(),
            "controllers".as_ref(),
        ],
    )?;
    let controllers: Vec<Principal> = serde_cbor::from_slice(controllers)?;
    cert.verify(
        canister_id.as_slice(),
        &agent.read_root_key(),
        &(time as u128), // pass the certificate time as current time in order to skip time verification
        &0,
    )?;
    Ok(PublicInfo {
        canister_id,
        module_hash,
        controllers,
        time,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let fetch_root_key = args.url != URL;
    let agent = Agent::builder().with_url(args.url).build()?;
    if fetch_root_key {
        agent.fetch_root_key().await?;
    }
    match &args.command {
        Command::Fetch { canister } => {
            let canister_id =
                Principal::from_text(canister).map_err(|_| "Please give a valid principal id")?;
            let info = canister_info(&agent, canister_id).await?;
            println!("{}", to_string(&info));
        }
        Command::Verify => {
            let mut buffer = String::new();
            let mut input = stdin();
            input.read_to_string(&mut buffer)?;
            let info: CanisterInfo = from_str(&buffer)?;
            println!("{}", to_string(&verify_info(&agent, &info)?));
        }
    };
    Ok(())
}
