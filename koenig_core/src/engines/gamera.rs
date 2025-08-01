//! Gamera engine; compact & ultra-lightweight obfuscation
//! Primarily for speed and simplicity, it performs reversible per-byte XOR
//! Transformations based on a rotating seed schedule. This engine does not
//! Rely on encryption and is intentionally stateless and trivial to reverse
//! Used on strings you want obfuscated but not bloated and not sensitive

use crate::Encryptor;

pub struct Gamera;

impl Gamera {
    /// Core reversible transformation: `b ^ ((seed + i).rotL(3) ^ 0x6D + i*11)`
    ///
    /// Used for both encryption and decryption
    ///
    /// # Arguments
    /// - `input`: The input byte slice to transform
    /// - `seed`: A single-byte entropy value
    ///
    /// # Returns
    /// - A new `Vec<u8>` containing the transformed output
    #[inline(always)]
    fn transform(input: &[u8], seed: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for (i, &b) in input.iter().enumerate() {
            let idx = i as u8;
            let rot = seed.wrapping_add(idx).rotate_left(3);
            let xor_val = (rot ^ 0x6D).wrapping_add(idx.wrapping_mul(11));
            out.push(b ^ xor_val);
        }
        out
    }

    /// Returns a dummy 4*8-byte fragment pair
    ///
    /// Gamera does not use real key masking, so it returns zeroed placeholders
    #[inline(always)]
    fn dummy_fragments() -> ([[u8; 8]; 4], [[u8; 8]; 4]) {
        ([[0u8; 8]; 4], [[0u8; 8]; 4])
    }

    /// Returns a zeroed dummy 32-byte tag
    ///
    /// No MAC is generated for this engine
    #[inline(always)]
    fn dummy_tag() -> [u8; 32] {
        [0u8; 32] // lol
    }
}

impl Encryptor for Gamera {
    /// Obfuscates plaintext using the Gamera transformation routine
    ///
    /// Returns the transformed ciphertext and dummy tag/fragments for API alignment and RE misleading
    ///
    /// # Arguments
    /// - `plain`: Input plaintext bytes.
    /// - `seed`: The seed used to drive the transformation
    ///
    /// # Returns
    /// - `(ciphertext, tag, frag, mask)` - only the ciphertext is meaningful
    #[inline(always)]
    fn encrypt(plain: &[u8], seed: u8) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        let ct = Self::transform(plain, seed);
        let (frag, mask) = Self::dummy_fragments();
        (ct, Self::dummy_tag(), frag, mask)
    }

    /// Reverses the transformation to recover the original str
    ///
    /// # Arguments
    /// - `ct`: Ciphertext to decrypt
    /// - `_tag`: Unused (present for API alignment)
    /// - `_frag`: Unused dummy fragment
    /// - `_mask`: Unused dummy mask
    /// - `seed`: The original transformation seed
    ///
    /// # Returns
    /// - Decrypted UTF-8 `String`
    ///
    /// # Panics
    /// - If the decrypted output is not valid UTF-8
    #[inline(always)]
    fn decrypt(
        ct: &[u8],
        _tag: &[u8],
        _frag: [[u8; 8]; 4],
        _mask: [[u8; 8]; 4],
        seed: u8,
    ) -> String {
        let pt = Self::transform(ct, seed);
        String::from_utf8(pt).expect("Gamera: invalid UTF-8")
    }
}