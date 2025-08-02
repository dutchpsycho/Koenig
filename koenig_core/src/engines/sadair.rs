//! # Sadair Engine
//!
//! **Sadair** is an implant-grade authenticated encryption engine using **AES-256-GCM** with:
//!
//! - Ephemeral per-call keying
//! - Runtime-derived nonce mutation based on a caller seed
//! - XOR-based post-mutation of ciphertext for AV/EDR obfuscation
//! - Tag fragmentation with 2 real + 2 decoy fragments to mislead RE/memory analysis
//!
//! It is best suited for high-sensitivity strings and buffers that must remain encrypted until runtime.

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::Encryptor;

/// AES-GCM-based ephemeral encryption engine for high-security red-team buffers.
pub struct Sadair;

impl Sadair {
    /// Masks a 32-byte key into 4×8-byte fragments and 4×8-byte masks.
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

    /// Builds a randomized 12-byte nonce using XOR-masked seed rotation.
    #[inline(always)]
    fn make_nonce(seed: u8) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let rotated: [u8; 12] = std::array::from_fn(|i| seed.rotate_left((i % 5) as u32));
        nonce.iter_mut().zip(rotated.iter()).for_each(|(n, r)| *n ^= r);
        nonce
    }

    /// Post-mutation of ciphertext: XOR every byte based on seed and index.
    #[inline(always)]
    fn post_mutate(buf: &mut [u8], seed: u8) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b ^= seed.rotate_left((i % 5) as u32) ^ 0xB3;
        }
    }

    /// Splits a 16-byte AES-GCM tag into 4×8-byte fragments (2 real + 2 decoys).
    #[inline(always)]
    fn fragment_tag(tag: &[u8; 16]) -> [[u8; 8]; 4] {
        let mut frags = [[0u8; 8]; 4];
        frags[0].copy_from_slice(&tag[..8]);
        frags[1].copy_from_slice(&tag[8..]);
        for i in 2..4 {
            OsRng.fill_bytes(&mut frags[i]);
        }
        frags
    }

    /// Reconstructs key from masked fragments.
    #[inline(always)]
    fn rebuild_key(fragments: [[u8; 8]; 4], masks: [[u8; 8]; 4]) -> [u8; 32] {
        let mut key = [0u8; 32];
        for (chunk, (frag_row, mask_row)) in
            key.chunks_mut(8).zip(fragments.iter().zip(masks.iter()))
        {
            for ((slot, &f), &m) in chunk.iter_mut().zip(frag_row.iter()).zip(mask_row.iter()) {
                *slot = f ^ m;
            }
        }
        key
    }
}

impl Encryptor for Sadair {
    #[inline(always)]
    fn encrypt(
        plain: &[u8],
        seed: u8,
    ) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
        let nonce_bytes = Self::make_nonce(seed);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = cipher
            .encrypt(nonce, plain)
            .expect("sadair: encryption failed");

        let tag_raw: [u8; 16] = ciphertext[ciphertext.len() - 16..].try_into().unwrap();
        let tag_frags = Self::fragment_tag(&tag_raw);

        Self::post_mutate(&mut ciphertext, seed);

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        let (fragments, masks) = Self::mask_key(&key);
        key.zeroize();

        // Reassemble 32-byte fake MAC from tag fragments
        let mut tag = [0u8; 32];
        for i in 0..4 {
            tag[i * 8..(i + 1) * 8].copy_from_slice(&tag_frags[i]);
        }

        (output, tag, fragments, masks)
    }

    #[inline(always)]
    fn decrypt(
        ct: &[u8],
        _tag: &[u8],
        fragments: [[u8; 8]; 4],
        masks: [[u8; 8]; 4],
        seed: u8,
    ) -> String {
        if ct.len() < 12 + 16 {
            panic!("sadair: invalid ciphertext (too short)");
        }

        let nonce = Nonce::from_slice(&ct[..12]);
        let mut ct_body = ct[12..].to_vec();
        Self::post_mutate(&mut ct_body, seed);

        let key = Self::rebuild_key(fragments, masks);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));

        let plaintext = cipher
            .decrypt(nonce, ct_body.as_slice())
            .expect("sadair: decryption failed");

        Zeroize::zeroize(&mut ct_body);
        Zeroize::zeroize(&mut plaintext.clone());

        String::from_utf8(plaintext).expect("sadair: invalid UTF-8")
    }
}
