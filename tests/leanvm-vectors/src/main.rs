//! Test vectors for the device port: key generation from a master seed, and
//! signatures, straight from leanVM's `sphincs` crate. Prints JSON on stdout.

use sphincs::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let seeds: [[u8; 32]; 3] = [[0x11; 32], [0x42; 32], std::array::from_fn(|i| i as u8)];
    let messages: [[u8; 32]; 2] = [std::array::from_fn(|i| (i * 5 + 3) as u8), [0xFF; 32]];
    let mut entries = Vec::new();
    for seed in &seeds {
        let (sk, pk) = key_gen_from_seed(*seed);
        for message in &messages {
            let sig = sign(&sk, message).expect("signing failed");
            verify(&pk, message, &sig).expect("reference signature does not verify");
            entries.push(format!(
                "    {{\"seed\": \"{}\", \"public_param\": \"{}\", \"root\": \"{}\", \"message\": \"{}\", \"counters\": {:?}, \"signature\": \"{}\"}}",
                hex(seed),
                hex(&pk.public_param),
                hex(&pk.root),
                hex(message),
                sig.counters,
                hex(&sig.to_bytes())
            ));
        }
    }
    println!(
        "{{\n  \"scheme\": \"leanVM SPHINCS+ (BLAKE2s, WOTS+C, FORS+C), doc/sphincs/main.tex\",\n  \"signature_bytes\": {SIG_SIZE},\n  \"vectors\": [\n{}\n  ]\n}}",
        entries.join(",\n")
    );
}
