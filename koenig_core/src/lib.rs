// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025 TITAN Softwork Solutions

/*!
 * ==================================================================================
 *  Repository:   KOENIG
 *  Project:      TSS
 *  File:         koenig_core lib
 *  Organization: TITAN Softwork Solutions
 *
 *  Description:
 *  KOENIG is a compile-time macro encryption framework for Rust,
 *  designed to protect embedded string literals via high-entropy encryption
 *  engines. Each engine is tailored to an encryption preference,
 *
 *  Absolut: Ascon128 X KMAC256
 *  Gamera: Complex inline assembly
 *  Jesko: ChaCha20 X Blake3
 *  Sadair: AES-GCM-256
 *
 *  License:      GNU Affero General Public License v3.0 (AGPL-3.0)
 *  Copyright:    (C) 2025 TITAN Softwork Solutions. All rights reserved.
 *
 *  Licensing Terms:
 *  ----------------------------------------------------------------------------------
 *   - You are free to use, modify, and share this software under the terms of AGPL-3.0.
 *   - All derivative works must also be licensed under AGPL-3.0.
 *   - Commercial use, distribution, or deployment must adhere to AGPL obligations.
 *   - Proper attribution must be given to TITAN Softwork Solutions.
 *   - Modifications must be clearly documented.
 *   - This software is provided "as-is" without warranties of any kind.
 *
 *  Full License: https://www.gnu.org/licenses/agpl-3.0.html
 * ==================================================================================
 */

pub const LICENSE: &str = "AGPL-3.0 © 2025 TITAN Softwork Solutions | KOENIG";

pub mod engines;

use engines::*;

/// Used to dispatch encryption based on input
#[derive(Debug, Clone, Copy)]
pub enum KoenigEngine {
    /// Jesko - stream cipher w/ keyed BLAKE3
    Jesko,
    /// Absolut - hardened Jesko variant
    Absolut,
    /// Sadair - AES-256-GCM + entropy masking
    Sadair,
    /// Gamera - fast obfuscator (non-crypto)
    Gamera,
}

impl KoenigEngine {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "jesko" => Some(Self::Jesko),
            "absolut" => Some(Self::Absolut),
            "sadair" => Some(Self::Sadair),
            "gamera" => Some(Self::Gamera),
            _ => None,
        }
    }
}

/// KOENIG Encryptor Trait
///
/// Implemented by each engine. Used by macros and dispatchers
pub trait Encryptor {
    /// Encrypt a plaintext with given seed, Returns:
    /// - Encrypted payload
    /// - 32-byte tag (MAC, padding, or dummy)
    /// - 32-byte key fragment (4*8)
    /// - 32-byte key mask (4*8)
    fn encrypt(
        plain: &[u8],
        seed: u8,
    ) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]);

    /// Decrypt using all encrypted data parts + original seed
    ///
    /// Returns the plaintext as a UTF-8 string
    fn decrypt(
        ct: &[u8],
        tag: &[u8],
        frag: [[u8; 8]; 4],
        mask: [[u8; 8]; 4],
        seed: u8,
    ) -> String;
}

/// Unified encrypt dispatcher for all KOENIG engines
///
/// Internally routes to the correct engine's `Encryptor::encrypt`
///
/// # Example
/// ```rust
/// use koenig::{pulse, KoenigEngine};
/// let (ct, tag, frag, mask) = pulse(KoenigEngine::Sadair, b"redline", 99);
/// ```
pub fn pulse(
    engine: KoenigEngine,
    plain: &[u8],
    seed: u8,
) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
    match engine {
        KoenigEngine::Jesko   => jesko::Jesko::encrypt(plain, seed),
        KoenigEngine::Absolut => absolut::Absolut::encrypt(plain, seed),
        KoenigEngine::Sadair  => sadair::Sadair::encrypt(plain, seed),
        KoenigEngine::Gamera  => gamera::Gamera::encrypt(plain, seed),
    }
}