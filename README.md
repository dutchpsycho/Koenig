# Koenig

Koenig is a Rust compile-time encryption tool that provides compile-time macros and a runtime core library to securely encrypt and decrypt strings. Koenig is extremely easy to embed in already existant codebases and usage requires minimal changes, Koenig's core cryptography engines are also exposed for usage.

## FEATURES

- **Multiple encryption engines**: Jesko, Absolut, Sadair, Gamera.
- **MAC verifcation** on-execution data tamper protection.
- **Mutli-string encryption**: To encrypt large amounts of data.

## CRATE STRUCTURE

- **koenig**: Umbrella crate re-exporting `koenig_core` and `koenig_macros`.  
- **koenig_core**: Core runtime library with encryption and decryption functions.  
- **koenig_macros**: Procedural macros for compile-time encryption and key expansion.

## INSTALL

Add the published crates to your `Cargo.toml`:

```toml
[dependencies]
koenig = "0.1.0"
````

If you need only the core library or macros crate:

```toml
koenig_core  = "0.1.0"
koenig_macros = "0.1.0"
```

For local development (before publishing):

```toml
[dependencies]
koenig        = { path = "./koenig" }
koenig_core   = { path = "./koenig_core" }
koenig_macros = { path = "./koenig_macros" }
```

## QUICK START

```rust
use koenig::{jesko, jeskoex};

fn main() {
    // Encrypt a single literal at compile time
    let secret: String = jesko!("MySecretData");

    // Encrypt multiple literals at compile time
    let keys: [String; 2] = jeskoex!("KeyOne", "KeyTwo");

    println!("Secret: {}", secret);
    println!("Keys: {:?}", keys);
}
```

## ENGINE MACROS

| Macro          | What it does                                               |
| -------------- | ---------------------------------------------------------- |
| `jesko!()`     | ChaCha20XBlake3 & MAC Authentication.                      |
| `absolut!()`   | Ascon128 X KMAC256                                         |
| `sadair!()`    | AES-GCM-256                                                |
| `gamera!()`    | Complex-inline assembly                                    |

All macros expand to a `String` (or `[String; N]` for the `*ex!` variants), embedding encrypted data in your compiled binary.

## CORE LIB

For advanced or dynamic use, `koenig_core` exposes an `Encryptor` trait and functions for direct encryption/decryption:

```rust
use koenig_core::{Encryptor, aes_gcm_encrypt, aes_gcm_decrypt};

let ciphertext = aes_gcm_encrypt(b"payload", b"32-byte key here");
let plaintext  = aes_gcm_decrypt(&ciphertext, b"32-byte key here")?;
assert_eq!(plaintext, b"payload");
```

Refer to the **koenig\_core** documentation for full API details.

## CLI DIAGNOSTICS

A binary runner is provided for manual diagnostics. From the workspace root:

```bash
cargo run --bin spec
```

Output:

```
==============================
RUNNING KOENIG ENGINE DIAGNOSTIC

[[ JESKO ENGINE ]]
> jesko:     ...
> jeskoex[0]: ...
> jeskoex[1]: ...

... (other engines)

ALL DIAGNOSTIC TESTS COMPLETED
==============================
```

## TESTING

Run all unit and integration tests:

```bash
cargo test --workspace
```

Run only the integration suite:

```bash
cargo test -p koenig_tests
```

Run the diagnostic binary under `cargo test` with output:

```bash
cargo test --test spec -- --nocapture
```

## LICENSE

This project is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0).
Full text in [LICENSE](LICENSE).

```
SPDX-License-Identifier: AGPL-3.0-or-later  
Copyright © 2025 TITAN Softwork Solutions
```

## CONTRIBUTING

Contributions are welcome. Please:

1. Fork the repository.
2. Create a descriptive branch name (e.g. `feature/add-jeskoex-support`).
3. Run `cargo fmt` and `cargo clippy --all` before submitting.
4. Open a pull request with a clear description and test coverage.

---

For questions or support, file an issue on the [GitHub repository](https://github.com/dutchpsycho/KOENIG).
