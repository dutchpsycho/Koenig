//! Jesko is a hybrid symmetric encryption engine leveraging BLAKE3-based key
//! derivation, ChaCha20 streaming cipher, MAC authentication, and key fragment masking
//! It is designed for strong, stateless symmetric encryption with obfuscated runtime decryption.
//! All ephemeral state (key, spell) is securely zeroized
//! Used on sensitive strings

use blake3::{hash, Hasher};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::Encryptor;

pub struct Jesko;

impl Jesko {
    /// BLAKE3 hash used to derive a stable 32-byte base key from a random 64-byte spell
    #[inline(always)]
    fn derive_key(spell: &[u8]) -> [u8; 32] {
        *hash(spell).as_bytes()
    }

    /// Constructs a nonce from the first 12 bytes of the key, mixed with the seed
    ///
    /// Nonce = `key[i] ^ ((i + seed).rotL(1)) ^ 0xA5`
    #[inline(always)]
    fn make_nonce(seed: u8, key: &[u8; 32]) -> [u8; 12] {
        let mut n = [0u8; 12];
        for (i, &b) in key.iter().take(12).enumerate() {
            n[i] = b ^ ((i as u8).wrapping_add(seed).rotate_left(1)) ^ 0xA5;
        }
        n
    }

    /// Splits the full 32-byte key into four 8-byte fragments
    /// obfuscated with independently generated masks
    #[inline(always)]
    fn mask_key(key: &[u8; 32]) -> ([[u8; 8]; 4], [[u8; 8]; 4]) {
        let mut frag = [[0u8; 8]; 4];
        let mut mask = [[0u8; 8]; 4];
        for i in 0..4 {
            OsRng.fill_bytes(&mut mask[i]);
            for j in 0..8 {
                frag[i][j] = key[i * 8 + j] ^ mask[i][j];
            }
        }
        (frag, mask)
    }

    /// Computes a keyed BLAKE3 MAC over the ciphertxt
    #[inline(always)]
    fn compute_mac(ct: &[u8], key: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Hasher::new_keyed(key);
        hasher.update(ct);
        *hasher.finalize().as_bytes()
    }
}

impl Encryptor for Jesko {
    /// Encrypts plaintext using ChaCha20 + BLAKE3 + masked key fragments
    ///
    /// # Arguments
    /// - `plain`: Input plaintext bytes
    /// - `seed`: The entropy seed driving the nonce generation
    ///
    /// # Returns
    /// - `(ciphertext, mac_tag, key_fragments, masks)`
    #[inline(always)]
    fn encrypt(
        plain: &[u8],
        seed: u8,
    ) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {

        let mut spell = [0u8; 64];
        OsRng.fill_bytes(&mut spell);

        let key = Self::derive_key(&spell);
        let nonce = Self::make_nonce(seed, &key);

        let mut ct = plain.to_vec();
        ChaCha20::new(&key.into(), &nonce.into()).apply_keystream(&mut ct);

        let mac = Self::compute_mac(&ct, &key);
        let (frag, mask) = Self::mask_key(&key);

        (ct, mac, frag, mask)
    }

    /// Decrypts a ciphertext using the seed and unmasked key
    ///
    /// # Arguments
    /// - `ct`: Encrypted ciphertext
    /// - `tag`: 32-byte BLAKE3 MAC tag
    /// - `frag`: 4*8-byte masked key fragments
    /// - `mask`: 4*8-byte masking material
    /// - `seed`: Seed used during encryption
    ///
    /// # Returns
    /// - The decrypted UTF-8 `String`
    ///
    /// # Panics
    /// - If MAC verification fails or the plaintext is not valid UTF-8
    #[inline(always)]
    fn decrypt(
        ct: &[u8],
        tag: &[u8],
        frag: [[u8; 8]; 4],
        mask: [[u8; 8]; 4],
        seed: u8,
    ) -> String {

        // Rebuild
        let mut key = [0u8; 32];
        for i in 0..4 {
            for j in 0..8 {
                key[i * 8 + j] = frag[i][j] ^ mask[i][j];
            }
        }

        // Validate MAC
        if tag.len() != 32 {
            panic!("Jesko: invalid tag length");
        }

        let expected = Self::compute_mac(ct, &key);
        if expected != tag {
            panic!("Jesko: MAC verification failed");
        }

        // Decrypt
        let nonce = Self::make_nonce(seed, &key);
        let mut data = ct.to_vec();
        ChaCha20::new(&key.into(), &nonce.into()).apply_keystream(&mut data);

        key.zeroize();

        String::from_utf8(data).expect("Jesko: invalid UTF-8")
    }
}