use std::env;
use std::process::ExitCode;

use libcrux_kem::{key_gen_derand, Algorithm as KemAlgorithm};

fn usage() -> &'static str {
    "usage: libcrux-import-check consistency <ML-KEM-*|ML-DSA-*> <seed_hex> <expanded_hex>"
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex input must have even length".to_string());
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_nibble(bytes[index]).ok_or_else(|| "invalid hex input".to_string())?;
        let lo = hex_nibble(bytes[index + 1]).ok_or_else(|| "invalid hex input".to_string())?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn check_mlkem(parameter_set: &str, seed: &[u8], expanded: &[u8]) -> Result<bool, String> {
    let alg = match parameter_set {
        "ML-KEM-512" => KemAlgorithm::MlKem512,
        "ML-KEM-768" => KemAlgorithm::MlKem768,
        "ML-KEM-1024" => KemAlgorithm::MlKem1024,
        _ => return Err(format!("unsupported ML-KEM parameter set: {parameter_set}")),
    };
    let (private_key, _) =
        key_gen_derand(alg, seed).map_err(|err| format!("libcrux ML-KEM key generation failed: {err:?}"))?;
    Ok(private_key.encode() == expanded)
}

fn check_mldsa(parameter_set: &str, seed: &[u8], expanded: &[u8]) -> Result<bool, String> {
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| "ML-DSA consistency check requires a 32-byte seed".to_string())?;
    let generated = match parameter_set {
        "ML-DSA-44" => libcrux_ml_dsa::ml_dsa_44::generate_key_pair(seed)
            .signing_key
            .as_slice()
            .to_vec(),
        "ML-DSA-65" => libcrux_ml_dsa::ml_dsa_65::generate_key_pair(seed)
            .signing_key
            .as_slice()
            .to_vec(),
        "ML-DSA-87" => libcrux_ml_dsa::ml_dsa_87::generate_key_pair(seed)
            .signing_key
            .as_slice()
            .to_vec(),
        _ => return Err(format!("unsupported ML-DSA parameter set: {parameter_set}")),
    };
    Ok(generated == expanded)
}

fn run() -> Result<bool, String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        return Err(usage().to_string());
    }
    let command = args[1].as_str();
    if command != "consistency" {
        return Err(usage().to_string());
    }
    let parameter_set = args[2].as_str();
    let seed = decode_hex(&args[3])?;
    let expanded = decode_hex(&args[4])?;
    if parameter_set.starts_with("ML-KEM-") {
        return check_mlkem(parameter_set, &seed, &expanded);
    }
    if parameter_set.starts_with("ML-DSA-") {
        return check_mldsa(parameter_set, &seed, &expanded);
    }
    Err(format!("unsupported parameter set: {parameter_set}"))
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => {
            println!("match");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("mismatch");
            ExitCode::from(1)
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
