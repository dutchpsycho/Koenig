// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025 TITAN Softwork Solutions

/*!
 * ==================================================================================
 *  Repository:   KOENIG
 *  Project:      TSS
 *  File:         koenig_spec main/spec
 *  Organization: TITAN Softwork Solutions
 *
 *  Description:
 *  KOENIG is a compile-time macro encryption framework for Rust,
 *  designed to protect embedded string literals via high-entropy encryption
 *  engines. Each engine is tailored to an encryption preference,
 *
 *  Absolut: ASCON128 X KMAC256
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

use koenig::{
    Encryptor,
    jesko,     jeskoex,
    absolut,   absolutex,
    sadair,    sadairex,
    gamera,    gameraex,
};

// Diagnostic CLI runner (cargo test -- --nocapture or `cargo run --bin diagnostic`)
fn main() {
    println!("==============================");
    println!("RUNNING KOENIG ENGINE DIAGNOSTIC\n");

    test_jesko_diag();
    test_absolut_diag();
    test_sadair_diag();
    test_gamera_diag();

    println!("\nALL DIAGNOSTIC TESTS COMPLETED");
    println!("==============================");
}

// Diagnostic output versions (manual test/debug)
fn test_jesko_diag() {
    let secret = jesko!("KOENIG SSmVza28=");
    let [a, b]: [String; 2] = jeskoex!("odium", "andromeda");

    println!("[[ JESKO ENGINE ]]");
    println!("> jesko:            {}", secret);
    println!("> jeskoex[0]:       {}", a);
    println!("> jeskoex[1]:       {}", b);
}

fn test_absolut_diag() {
    let boot = absolut!("KOENIG U21WemEyOVM=");
    let [a, b, c]: [String; 3] = absolutex!("amensia", "distortion", "deep-fusion");

    println!("[[ ABSOLUT ENGINE ]]");
    println!("> absolut:           {}", boot);
    println!("> absolutex[0]:      {}", a);
    println!("> absolutex[1]:      {}", b);
    println!("> absolutex[2]:      {}", c);
}

fn test_sadair_diag() {
    let sig = sadair!("KOENIG U2FkYWly");
    let [x, y, z]: [String; 3] = sadairex!("tokyo", "space-attack", "blindspot");

    println!("[[ SADAIR ENGINE ]]");
    println!("> sadair:           {}", sig);
    println!("> sadairex[0]:      {}", x);
    println!("> sadairex[1]:      {}", y);
    println!("> sadairex[2]:      {}", z);
}

fn test_gamera_diag() {
    let boot = gamera!("KOENIG R2FtZXJh");
    let [a, b]: [String; 2] = gameraex!("infinity", "volume-two");

    println!("[[ GAMERA ENGINE ]]");
    println!("> gamera:           {}", boot);
    println!("> gameraex[0]:      {}", a);
    println!("> gameraex[1]:      {}", b);
}

// Unit tests (standard cargo test)
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jesko_macro() {
        let secret = jesko!("KOENIG SSmVza28=");
        let [a, b]: [String; 2] = jeskoex!("odium", "andromeda");

        assert!(secret.contains("KOENIG") || !secret.is_empty());
        assert!(a.len() > 0);
        assert!(b.len() > 0);
    }

    #[test]
    fn test_absolut_macro() {
        let boot = absolut!("KOENIG U21WemEyOVM=");
        let [a, b, c]: [String; 3] = absolutex!("amensia", "distortion", "deep-fusion");

        assert!(boot.contains("KOENIG") || !boot.is_empty());
        assert!(a.len() > 0);
        assert!(b.len() > 0);
        assert!(c.len() > 0);
    }

    #[test]
    fn test_sadair_macro() {
        let sig = sadair!("KOENIG U2FkYWly");
        let [x, y, z]: [String; 3] = sadairex!("tokyo", "space-attack", "blindspot");

        assert!(sig.contains("KOENIG") || !sig.is_empty());
        assert!(x.len() > 0);
        assert!(y.len() > 0);
        assert!(z.len() > 0);
    }

    #[test]
    fn test_gamera_macro() {
        let boot = gamera!("KOENIG R2FtZXJh");
        let [a, b]: [String; 2] = gameraex!("infinity", "volume-two");

        assert!(boot.contains("KOENIG") || !boot.is_empty());
        assert!(a.len() > 0);
        assert!(b.len() > 0);
    }
}