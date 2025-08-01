//! Sadair is a high-speed, authenticated AES-256-GCM engine with ephemeral keying and custom nonce derivation
//! It applies layered key-masking and randomized nonce mutation for runtime security
//! Used on high-sensitivty strings

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::Encryptor;

pub struct Sadair;

impl Sadair {
    /// Masks a 32-byte key using 4×8-byte fragments and masks
    ///
    /// Each `frag[i][j] = key[i*8 + j] ^ mask[i][j]`
    #[inline(always)]
    fn mask_key(key: &[u8; 32]) -> ([[u8; 8]; 4], [[u8; 8]; 4]) {
        let mut fragments = [[0u8; 8]; 4];
        let mut masks = [[0u8; 8]; 4];

        for (i, (frag_row, mask_row)) in fragments.iter_mut().zip(masks.iter_mut()).enumerate() {
            OsRng.fill_bytes(mask_row);
            for (j, &m) in mask_row.iter().enumerate() {
                frag_row[j] = key[i * 8 + j] ^ m;
            }
        }

        (fragments, masks)
    }

    /// Builds a nonce from random bytes XORed with rotated `seed`
    ///
    /// Nonce = `RNG[i] ^ seed.rotL(i % 5)`
    #[inline(always)]
    fn make_nonce(seed: u8) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let rotated: [u8; 12] = std::array::from_fn(|i| seed.rotate_left((i % 5) as u32));
        nonce.iter_mut().zip(&rotated).for_each(|(n, &r)| *n ^= r);

        nonce
    }
}

impl Encryptor for Sadair {
    /// Encrypts the input using AES-256-GCM, embedding the nonce in the ciphertext prefix
    ///
    /// # Arguments
    /// - `plain`: Input plaintext
    /// - `seed`: Entropy source for nonce mutation
    ///
    /// # Returns
    /// - `(nonce || ciphertext, padded_tag[32], key_fragments, key_masks)`
    #[inline(always)]
    fn encrypt(
        plain: &[u8],
        seed: u8,
    ) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        let nonce_bytes = Sadair::make_nonce(seed);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plain)
            .expect("sadair: AES-GCM encryption failed");

        let mut output = Vec::with_capacity(12 + ciphertext.len());

        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        let tag = {
            let mut padded = [0u8; 32];
            let start = ciphertext.len().saturating_sub(16);
            padded[..16].copy_from_slice(&ciphertext[start..]);
            padded
        };

        let (fragments, masks) = Sadair::mask_key(&key);
        key.zeroize();

        (output, tag, fragments, masks)
    }

    /// Decrypts a nonce-prefixed AES-GCM ciphertext using masked key frags
    ///
    /// # Arguments
    /// - `ct`: The full nonce-prefixed ciphertext.
    /// - `_tag`: Padded tag (unused — embedded in GCM).
    /// - `fragments`: Obfuscated key frags
    /// - `masks`: Random masks used during encryption.
    /// - `_seed`: (Unused) — nonce is embedded in ciphertext.
    ///
    /// # Returns
    /// - Decrypted UTF-8 str
    ///
    /// # Panics
    /// - If ciphertext is too short or decrypt fails
    #[inline(always)]
    fn decrypt(
        ct: &[u8],
        _tag: &[u8],
        fragments: [[u8; 8]; 4],
        masks: [[u8; 8]; 4],
        _seed: u8,
    ) -> String {
        let mut key = [0u8; 32];
        for (chunk, (frag_row, mask_row)) in
            key.chunks_mut(8).zip(fragments.iter().zip(masks.iter()))
        {
            for ((slot, &f), &m) in chunk.iter_mut().zip(frag_row.iter()).zip(mask_row.iter()) {
                *slot = f ^ m;
            }
        }

        if ct.len() < 12 + 16 {
            panic!("sadair: invalid ciphertext (too short)");
        }

        let nonce = Nonce::from_slice(&ct[..12]);
        let ct_slice = &ct[12..];

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        let plaintext = cipher
            .decrypt(nonce, ct_slice)
            .expect("sadair: AES-GCM decryption failed");
        key.zeroize();

        String::from_utf8(plaintext).expect("sadair: invalid UTF-8")
    }
}