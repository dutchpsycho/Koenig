#![doc = r#"
# Jesko Engine

**Jesko** is a hybrid symmetric encryption engine tailored **stealth string encryption** scenarios.
It combines:

- `BLAKE3`-based stateless key derivation  
- `ChaCha20` stream encryption  
- Lightweight XOR-based post-mutation  
- `BLAKE3` MAC authentication  
- Key fragmentation and masking for memory obfuscation

It is **fast**, **portable**, and designed to **avoid traditional cryptographic signatures**, while remaining secure enough for sensitive short-lived data like payload strings, C2 tokens, or runtime config blobs.

Implements the [`Encryptor`](crate::Encryptor) trait.
"#]

use chacha20::ChaCha20 as StreamX;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use blake3::{Hasher as B3Hasher, hash as bl3_hash};

use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::Encryptor;

/// Jesko provides stealth-grade string encryption for short-lived sensitive data.
///
/// Unlike traditional AEADs, Jesko does not store the nonce alongside the ciphertext,
/// relying on a reproducible (but obfuscated) derivation based on a caller-provided `seed`.
///
/// Used primarily for:
/// - Config strings
/// - Payload staging
/// - Runtime string obfuscation in AV/EDR-hostile environments
pub struct Jesko;

/// Internal masked key container used to store XOR-fragmented key material
/// alongside per-fragment 8-byte masks.
#[repr(C)]
struct MaskedKey {
    /// 4x8 bytes of XOR-masked key fragments
    frag: [[u8; 8]; 4],
    /// 4x8 byte masks used to recover original key
    mask: [[u8; 8]; 4],
}

impl Jesko {
    /// Derives a 256-bit key from a 64-byte spell using BLAKE3.
    ///
    /// # Arguments
    /// - `spell`: Randomly generated entropy input
    ///
    /// # Returns
    /// - `[u8; 32]` – the derived symmetric key
    #[inline(always)]
    fn derive_key(spell: &[u8]) -> [u8; 32] {
        *bl3_hash(spell).as_bytes()
    }

    /// Constructs a deterministic, seed-obfuscated nonce from the first 12 bytes of the key.
    ///
    /// # Arguments
    /// - `seed`: Runtime seed value
    /// - `key`: The full derived 256-bit key
    ///
    /// # Returns
    /// - `[u8; 12]` nonce for ChaCha20
    #[inline(always)]
    fn make_nonce(seed: u8, key: &[u8; 32]) -> [u8; 12] {
        let mut n = [0u8; 12];
        for (i, &b) in key.iter().take(12).enumerate() {
            n[i] = b ^ ((i as u8).wrapping_add(seed).rotate_left(1)) ^ 0xA5;
        }
        n
    }

    /// Applies post-encryption XOR mutation to ciphertext.
    ///
    /// Helps prevent pattern matching on raw ChaCha20 output.
    #[inline(always)]
    fn post_mutate(buf: &mut [u8], seed: u8) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b ^= seed.rotate_left((i % 5) as u32) ^ 0x9B;
        }
    }

    /// Splits a 256-bit key into four 64-bit fragments, each masked with random 8-byte junk.
    ///
    /// # Returns
    /// - `MaskedKey` – XOR-fragmented structure holding real key material and masks
    #[inline(always)]
    fn mask_key(key: &[u8; 32]) -> MaskedKey {
        let mut frag = [[0u8; 8]; 4];
        let mut mask = [[0u8; 8]; 4];
        for i in 0..4 {
            OsRng.fill_bytes(&mut mask[i]);
            for j in 0..8 {
                frag[i][j] = key[i * 8 + j] ^ mask[i][j];
            }
        }
        MaskedKey { frag, mask }
    }

    /// Computes a keyed BLAKE3 MAC tag over the ciphertext.
    ///
    /// # Arguments
    /// - `ct`: The ciphertext to tag
    /// - `key`: The full derived key
    ///
    /// # Returns
    /// - `[u8; 32]` – authentication tag
    #[inline(always)]
    fn compute_mac(ct: &[u8], key: &[u8; 32]) -> [u8; 32] {
        let mut h = B3Hasher::new_keyed(key);
        h.update(ct);
        *h.finalize().as_bytes()
    }
}

impl Encryptor for Jesko {
    /// Encrypts plaintext using:
    /// 1. BLAKE3 key derivation from a random `spell`
    /// 2. Deterministic seed-mixed nonce
    /// 3. ChaCha20 stream encryption
    /// 4. XOR mutation of ciphertext
    /// 5. MAC tagging and key fragmentation
    ///
    /// # Returns
    /// - `(ciphertext, mac_tag, key_fragments, mask)`
    #[inline(always)]
    fn encrypt(
        plain: &[u8],
        seed: u8,
    ) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        let mut spell = [0u8; 64];
        OsRng.fill_bytes(&mut spell);

        let mut key = Self::derive_key(&spell);
        let nonce = Self::make_nonce(seed, &key);
        let mut nonce_copy = nonce;
        let mut ct = plain.to_vec();

        StreamX::new(&key.into(), &nonce.into()).apply_keystream(&mut ct);
        Self::post_mutate(&mut ct, seed);

        let mac = Self::compute_mac(&ct, &key);
        let MaskedKey { frag, mask } = Self::mask_key(&key);

        key.zeroize();
        spell.zeroize();
        nonce_copy.zeroize();

        (ct, mac, frag, mask)
    }

    /// Decrypts the ciphertext using reconstructed key and nonce.
    ///
    /// # Panics
    /// - If MAC verification fails
    /// - If the tag is invalid or length is incorrect
    /// - If output is not valid UTF-8
    #[inline(always)]
    fn decrypt(
        ct: &[u8],
        tag: &[u8],
        frag: [[u8; 8]; 4],
        mask: [[u8; 8]; 4],
        seed: u8,
    ) -> String {
        let mut key = [0u8; 32];
        for i in 0..4 {
            for j in 0..8 {
                key[i * 8 + j] = frag[i][j] ^ mask[i][j];
            }
        }

        if tag.len() != 32 {
            panic!("Jesko: invalid tag length");
        }

        let expected = Self::compute_mac(ct, &key);
        if expected != tag {
            panic!("Jesko: MAC verification failed");
        }

        let nonce = Self::make_nonce(seed, &key);
        let mut nonce_copy = nonce;
        let mut data = ct.to_vec();

        Self::post_mutate(&mut data, seed);
        StreamX::new(&key.into(), &nonce.into()).apply_keystream(&mut data);

        key.zeroize();
        nonce_copy.zeroize();

        String::from_utf8(data).expect("Jesko: invalid UTF-8")
    }
}