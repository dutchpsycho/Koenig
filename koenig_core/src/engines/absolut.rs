#![doc = r#"
# Absolut Engine

**Absolut** is a hardened, implant-grade encryption engine that prioritizes **runtime stealth**, **AV/EDR evasion**, and **entropy control** over traditional compliance.  
It utilizes a [KMAC256](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)-based key derivation model and the [ASCON128](https://ascon.iaik.tugraz.at/) authenticated cipher.

This engine is built for **high-sensitivity payloads**, where detection resistance matters more than standard cryptographic auditability.

Implements the [`Encryptor`](crate::Encryptor) trait.
"#]

use std::time::{SystemTime, UNIX_EPOCH};

use ascon_aead::{AsconAead128, AsconAead128Key, AsconAead128Nonce};
use ascon_aead::aead::{Aead, KeyInit, Payload};
use tiny_keccak::{Kmac, Hasher};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::Encryptor;

/// Absolut is a hardened, stealth-optimized encryption engine designed for red team ops,
/// high-entropy string protection, and runtime memory concealment.
///
/// Features:
/// - KMAC256-derived keying based on a randomized "spell" and time-based domain
/// - Nonce mutation using key material and seed-driven shifts
/// - ASCON128 AEAD cipher for lightweight, stealthy encryption
/// - Post-encryption mutation to prevent ciphertext fingerprinting
/// - Key fragmentation into decoy-packed memory buckets
///
/// This engine **assumes attacker model includes memory forensics**.
/// It prioritizes stealth over simplicity or performance.
pub struct Absolut;

/// First-stage fragmented key structure.
#[repr(C)]
pub struct FragmentBucketA {
    /// Initial 6 bytes of the derived key
    pub a: [u8; 6],
    /// Key continuation byte (hidden position)
    pub hidden: u8,
    /// Padding byte (inert)
    pub pad: u8,
}

/// Second-stage fragmented key structure.
#[repr(C)]
pub struct FragmentBucketB {
    /// Mid-key block (low entropy, used in MAC and nonce gen)
    pub x: u32,
    /// High-key block (entropy injection for mutation)
    pub y: u32,
    /// Static decoy bytes for memory misdirection
    pub decoy: [u8; 4],
}

impl Absolut {
    /// Derives a 128-bit key using KMAC256 with time-randomized domain separation.
    ///
    /// The resulting key is fragmented into two `FragmentBucket` structures, partially masked
    /// and containing decoy values to break memory pattern recognition.
    ///
    /// # Arguments
    /// - `spell`: 64-byte entropy input
    /// - `seed`: Rotational entropy injection
    ///
    /// # Returns
    /// - `(FragmentBucketA, FragmentBucketB)`
    #[inline(always)]
    fn derive_key_kmac256(spell: &[u8], seed: u8) -> (FragmentBucketA, FragmentBucketB) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let ts = now.to_le_bytes();

        let mut domain = [0u8; 32];
        let mut custom = [0u8; 16];
        for i in 0..32 {
            domain[i] = ts[i % ts.len()] ^ seed.rotate_left(i as u32 % 5) ^ 0xA5;
        }
        for i in 0..16 {
            custom[i] = ts[i % ts.len()] ^ seed.rotate_left(i as u32 % 3) ^ 0xC3;
        }

        let mut kmac = Kmac::v256(&domain, &custom);
        kmac.update(spell);
        kmac.update(&[seed]);

        let mut full_key = [0u8; 16];
        kmac.finalize(&mut full_key);

        let frag_a = FragmentBucketA {
            a: [full_key[0], full_key[1], full_key[2], full_key[3], full_key[4], full_key[5]],
            hidden: full_key[6],
            pad: full_key[7],
        };

        let frag_b = FragmentBucketB {
            x: u32::from_le_bytes([full_key[8], full_key[9], full_key[10], full_key[11]]),
            y: u32::from_le_bytes([full_key[12], full_key[13], full_key[14], full_key[15]]),
            decoy: [0xAA, 0xBB, 0xCC, 0xDD],
        };

        full_key.zeroize();
        (frag_a, frag_b)
    }

    /// Builds a per-encryption 16-byte nonce by mutating fresh randomness with key material and seed.
    ///
    /// # Arguments
    /// - `seed`: Seed used to drive shifts
    /// - `key`: The 128-bit key to blend into the nonce
    ///
    /// # Returns
    /// - `[u8; 16]` – derived nonce
    #[inline(always)]
    fn make_nonce(seed: u8, key: &[u8; 16]) -> [u8; 16] {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        for i in 0..16 {
            nonce[i] ^= key[i] ^ seed.rotate_left(i as u32 % 6) ^ 0x9E;
        }
        nonce
    }

    /// Reassembles the actual encryption key from the two memory fragment buckets.
    ///
    /// # Returns
    /// - 128-bit ASCON key as `[u8; 16]`
    #[inline(always)]
    fn rebuild_key(fa: &FragmentBucketA, fb: &FragmentBucketB) -> [u8; 16] {
        let mut key = [0u8; 16];
        key[..6].copy_from_slice(&fa.a);
        key[6] = fa.hidden;
        key[7] = fa.pad;
        key[8..12].copy_from_slice(&fb.x.to_le_bytes());
        key[12..16].copy_from_slice(&fb.y.to_le_bytes());
        key
    }

    /// Applies a per-byte XOR-based post-mutation to the ciphertext after encryption.
    ///
    /// This obfuscates recognizable AEAD layout (e.g., tag position, padding entropy) to avoid
    /// detection by memory scanners or static signature engines.
    #[inline(always)]
    fn post_mutate(data: &mut [u8], seed: u8, mix: u8) {
        for (i, byte) in data.iter_mut().enumerate() {
            *byte ^= seed.rotate_left((i % 5) as u32) ^ mix.rotate_right((i % 7) as u32);
        }
    }
}

impl Encryptor for Absolut {
    /// Encrypts plaintext using:
    /// 1. KMAC256-based key derivation
    /// 2. Nonce mutation
    /// 3. ASCON128 AEAD encryption
    /// 4. Post-encryption XOR mutation
    /// 5. Key fragmentation
    ///
    /// # Returns
    /// - `(nonce || ciphertext, mac_tag, frag, mask)`
    fn encrypt(
        plain: &[u8],
        seed: u8,
    ) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        let mut spell = [0u8; 64];
        OsRng.fill_bytes(&mut spell);

        let (frag_a, frag_b) = Self::derive_key_kmac256(&spell, seed);
        let key = Self::rebuild_key(&frag_a, &frag_b);
        let nonce_bytes = Self::make_nonce(seed, &key);

        let cipher = AsconAead128::new(AsconAead128Key::from_slice(&key));
        let nonce = AsconAead128Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = cipher
            .encrypt(nonce, Payload { msg: plain, aad: &[] })
            .expect("absolut: encryption failed");

        Self::post_mutate(&mut ciphertext, seed, (frag_b.y & 0xFF) as u8);

        let mut frag = [[0u8; 8]; 4];
        let mut mask = [[0u8; 8]; 4];
        frag[0][..6].copy_from_slice(&frag_a.a);
        frag[0][6] = frag_a.hidden;
        frag[0][7] = frag_a.pad;
        frag[1][..4].copy_from_slice(&frag_b.x.to_le_bytes());
        frag[1][4..8].copy_from_slice(&frag_b.y.to_le_bytes());

        for i in 0..4 {
            OsRng.fill_bytes(&mut mask[i]);
        }

        let mut tag = [0u8; 32];
        tag[..16].copy_from_slice(&ciphertext[ciphertext.len() - 16..]);

        spell.zeroize();

        let mut full_ct = Vec::with_capacity(16 + ciphertext.len());
        full_ct.extend_from_slice(&nonce_bytes);
        full_ct.extend_from_slice(&ciphertext);

        (full_ct, tag, frag, mask)
    }

    /// Decrypts a ciphertext using the reassembled key and seed.
    ///
    /// # Panics
    /// - If the ciphertext is too short
    /// - If the ASCON decryption fails
    /// - If the output is not valid UTF-8
    fn decrypt(
        ct: &[u8],
        _tag: &[u8],
        frag: [[u8; 8]; 4],
        _mask: [[u8; 8]; 4],
        seed: u8,
    ) -> String {
        if ct.len() < 32 {
            panic!("absolut: ciphertext too short");
        }

        let frag_a = FragmentBucketA {
            a: [frag[0][0], frag[0][1], frag[0][2], frag[0][3], frag[0][4], frag[0][5]],
            hidden: frag[0][6],
            pad: frag[0][7],
        };

        let frag_b = FragmentBucketB {
            x: u32::from_le_bytes([frag[1][0], frag[1][1], frag[1][2], frag[1][3]]),
            y: u32::from_le_bytes([frag[1][4], frag[1][5], frag[1][6], frag[1][7]]),
            decoy: [0x00; 4],
        };

        let key = Self::rebuild_key(&frag_a, &frag_b);
        let nonce = AsconAead128Nonce::from_slice(&ct[..16]);
        let mut ct_body = ct[16..].to_vec();

        Self::post_mutate(&mut ct_body, seed, (frag_b.y & 0xFF) as u8);

        let cipher = AsconAead128::new(AsconAead128Key::from_slice(&key));
        let plain = cipher
            .decrypt(nonce, Payload { msg: &ct_body, aad: &[] })
            .expect("absolut: decryption failed");

        let mut key_copy = key;
        key_copy.zeroize();

        String::from_utf8(plain).expect("absolut: invalid UTF-8")
    }
}