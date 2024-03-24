/* Cargo.toml
[package]
name = "bf"
version = "0.1.0"
edition = "2021"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
base64 = "0.22.0"
hex = "0.4.3"
hmac = "0.12.1"
mt19937 = "2.0.1"
rand_mt = "4.2.2"
rayon = "1.9.0"
sha2 = "0.10.8"
*/

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use hmac::digest::FixedOutput;
use hmac::{Hmac, Mac};
use rand_mt::Mt19937GenRand32;
use rayon::prelude::*;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const CHARSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
fn next_rand(mt: &mut Mt19937GenRand32, a2: u32) -> u32 {
    let v2 = mt.next_u32();
    let _a2_u64 = a2 as u64;
    let mut v5 = _a2_u64 * (v2 as u64);
    if (v5 as u32) < a2 {
        let limit = (0x100000000u64 / _a2_u64 - 1) as u32;
        while (v5 as u32) < limit {
            let v3 = mt.next_u32();
            v5 = _a2_u64 * (v3 as u64);
        }
    }
    (v5 >> 32) as u32
}
fn generate(x: u32, to_verify: &str, hash: &[u8]) -> Option<String> {
    let mut mt = Mt19937GenRand32::new(x.into());
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = CHARSET[next_rand(&mut mt, CHARSET.len() as u32) as usize];
    }

    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(to_verify.as_bytes());

    let mut result_arr = [0u8; 32];
    mac.finalize_into((&mut result_arr).into());
    if result_arr == hash {
        Some(std::str::from_utf8(&key).unwrap().to_owned())
    } else {
        None
    }
}

fn main() {
    const CORES: usize = 96;
    let payload = std::env::args().nth(1).unwrap();
    let chunks: Vec<_> = payload.split('.').collect();
    let to_verify = chunks[0].to_owned() + "." + chunks[1];
    let hash = &URL_SAFE_NO_PAD.decode(chunks[2]).unwrap();
    eprintln!("{to_verify}");
    (0..CORES).into_par_iter().for_each(|x| {
        let to_verify = to_verify.clone();
        for i in (x as u32..0xffffffffu32).step_by(CORES) {
            if i % 0x1000000 == 0 {
                eprintln!("{i:08x}");
            }
            if let Some(key) = generate(i, &to_verify, hash) {
                eprintln!("Found {i} {key}");
                println!("{key}");
                std::process::exit(0);
            }
        }
    });
}
