use bee_crypto::Kerl;
use bee_signing::ternary::{
  PrivateKey, PrivateKeyGenerator, Seed, TernarySeed, WotsSecurityLevel,
  WotsSpongePrivateKeyGeneratorBuilder,
};
use bee_ternary::{T1B1Buf, TryteBuf};
use std::thread;
use std::time::Instant;

const SEED: &str =
  "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN";

fn main() {
  let time_start = Instant::now();
  let threads = 8;
  let total_addresses = 1000;
  let amount = total_addresses / threads;

  let seed_trits = TryteBuf::try_from_str(SEED)
    .unwrap()
    .as_trits()
    .encode::<T1B1Buf>();
  let seed = TernarySeed::<Kerl>::from_buf(seed_trits).unwrap();
  let arc_seed = std::sync::Arc::new(seed);

  let mut pool = vec![];
  for i in 0..threads {
    let s = arc_seed.clone();
    pool.push(thread::spawn(move || {
      if i == threads - 1 {
        generate_adresses(
          s,
          i * amount,
          ((i + 1) * amount) + total_addresses % threads,
        )
      } else {
        generate_adresses(s, i * amount, (i + 1) * amount)
      }
    }));
  }
  let mut addresses = Vec::new();
  for worker in pool {
    let second = worker.join().unwrap();
    addresses = [&addresses[..], &second[..]].concat();
  }
  println!("{:#?}", addresses);
  println!(
    "Generated {} addresses in {:.2?}",
    addresses.len(),
    time_start.elapsed()
  );
}

fn generate_adresses(
  seed: std::sync::Arc<TernarySeed<Kerl>>,
  start: usize,
  end: usize,
) -> std::vec::Vec<std::string::String> {
  let mut addresses = vec![String::from(""); end - start];
  for index in start..end {
    let private_key_generator = WotsSpongePrivateKeyGeneratorBuilder::<Kerl>::default()
      .security_level(WotsSecurityLevel::Medium)
      .build()
      .unwrap();
    let private_key = private_key_generator.generate(&seed, index as u64).unwrap();
    let public_key = private_key.generate_public_key().unwrap();
    addresses[index - start] = format!("{}: {}", index, public_key.to_string());
  }
  addresses
}
