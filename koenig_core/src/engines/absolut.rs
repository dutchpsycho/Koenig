//! Absolut is a high-entropy hardened variant of the Jesko engine
//! Used on highly sensitive strings

use blake3::{hash, Hasher as Blake3Hasher};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::Encryptor;

pub struct Absolut;

impl Absolut {
    /// Derives a 32-byte base key using BLAKE3 over a random "spell".
    #[inline(always)]
    fn derive_key(spell: &[u8]) -> [u8; 32] {
        *hash(spell).as_bytes()
    }

    /// Permutes a 32-byte base key using seed-based mixing and index-rot
    #[inline(always)]
    fn permute_key_heavy(base: &[u8; 32], seed: u8) -> [u8; 32] {
        let mut key = *base;
        for i in 0..32 {
            key[i] ^= seed
                .rotate_left((i as u32) % 7)
                ^ base[((i as u8).wrapping_add(seed) as usize) % 32];
            key[i] = key[i].rotate_right(((i as u8) ^ seed) as u32 % 8);
        }
        key
    }

    /// Generates a nonce using intra-key entropy + seed-based rot
    #[inline(always)]
    fn make_nonce_heavy(seed: u8, key: &[u8; 32]) -> [u8; 12] {
        let mut n = [0u8; 12];
        for i in 0..12 {
            let a = key[i];
            let b = key[(i + 1) % 12];
            n[i] = a ^ (b >> 2) ^ (seed.rotate_right(i as u32) ^ 0x5F);
        }
        n
    }

    /// Applies post-encryption mutation to ChaCha20 output using key/seed patterns
    #[inline(always)]
    fn post_mutate(data: &mut [u8], key: &[u8; 32], seed: u8) {
        for (i, byte) in data.iter_mut().enumerate() {
            let k = key[i % 32];
            let mix = k
                .rotate_left((i as u32 % 5) + 1)
                ^ seed.rotate_right(i as u32 % 7);
            *byte ^= mix;
        }
    }

    /// Computes a BLAKE3 MAC over the mutated ciphertext using the derived key
    #[inline(always)]
    fn compute_mac(ct: &[u8], key: &[u8; 32]) -> [u8; 32] {
        let mut h = Blake3Hasher::new_keyed(key);
        h.update(ct);
        *h.finalize().as_bytes()
    }

    /// Masks a 32-byte key into 4x8-byte fragments using random 8-byte masks
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
}

impl Encryptor for Absolut {
    /// 1. Generates spell
    /// 2. Derives a base key with BLAKE3 and permutes
    /// 3. Builds nonce
    /// 4. Encrypts w ChaCha20
    /// 5. Post-mutates the ciphertext
    /// 6. Computes a MAC & fragments the key
    /// 7. Zeroizes
    fn encrypt(
        plain: &[u8],
        seed: u8,
    ) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        let mut spell = [0u8; 64];
        OsRng.fill_bytes(&mut spell);

        let mut base = Self::derive_key(&spell);
        let mut key = Self::permute_key_heavy(&base, seed);

        base.zeroize();
        spell.zeroize();

        let nonce = Self::make_nonce_heavy(seed, &key);

        let mut ct = plain.to_vec();
        ChaCha20::new(&key.into(), &nonce.into()).apply_keystream(&mut ct);
        Self::post_mutate(&mut ct, &key, seed);

        let tag = Self::compute_mac(&ct, &key);
        let (frag, mask) = Self::mask_key(&key);

        key.zeroize();

        (ct, tag, frag, mask)
    }

    /// Verifies integrity using MAC, reverses post-mutation & decrypts with ChaCha20.
    ///
    /// # Panics
    /// - If MAC verification fails.
    /// - If output is not valid UTF-8.
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

        let calc = Self::compute_mac(ct, &key);
        if calc != *tag {
            panic!("Absolut: MAC verification failed");
        }

        let mut buf = ct.to_vec();
        Self::post_mutate(&mut buf, &key, seed);

        let nonce = Self::make_nonce_heavy(seed, &key);
        ChaCha20::new(&key.into(), &nonce.into()).apply_keystream(&mut buf);

        key.zeroize();

        String::from_utf8(buf).expect("Absolut: invalid UTF-8")
    }
}