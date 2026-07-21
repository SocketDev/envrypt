//! Embed example: read a `.env`, resolve the private key (env → `.env.keys`),
//! decrypt `encrypted:` values, and read them back. `load()` is strict and does
//! NOT mutate `std::env`.
//!
//! Run from a directory containing a `.env` (and, for encrypted values, an
//! `ENVRYPT_PRIVATE_KEY` env var or a sibling `.env.keys`). A Sockeye-approved
//! child receives the environment variable directly.
//!
//! ```text
//! cargo run --example load_then_read
//! ```

fn main() -> Result<(), envrypt::LoadError> {
  let loaded = envrypt::load()?;

  println!("resolved {} key(s):", loaded.len());
  for (key, value) in loaded.iter() {
    // Never print real secrets in a real app — this is illustrative.
    println!("  {key} = {value}");
  }

  if let Some(token) = loaded.get("STRIPE_SECRET") {
    eprintln!("STRIPE_SECRET resolved ({} bytes)", token.len());
  }

  Ok(())
}
