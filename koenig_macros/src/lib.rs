// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2025 TITAN Softwork Solutions

/*!
 * ==================================================================================
 *  Repository:   KOENIG
 *  Project:      TSS
 *  File:         koenig_macros lib
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

extern crate proc_macro;

use proc_macro::{TokenStream, TokenTree};
use proc_macro2::{Literal, TokenStream as TokenStream2};
use quote::quote;

use koenig_core::{KoenigEngine, pulse};

fn parse_literals(input: TokenStream) -> Vec<String> {
    input
        .into_iter()
        .filter_map(|tk| {
            if let TokenTree::Literal(lit) = tk {
                let s = lit.to_string();
                Some(s[1..s.len() - 1].to_string())
            } else {
                None
            }
        })
        .collect()
}

fn random_seed() -> u8 {
    use std::{
        arch::x86_64::__cpuid,
        collections::hash_map::DefaultHasher,
        fmt::Write,
        hash::Hasher,
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let pid = process::id();

    let tid_hash = {
        let mut s = String::new();
        write!(&mut s, "{:?}", std::thread::current().id()).unwrap();
        s.bytes()
            .enumerate()
            .fold(0u64, |acc, (i, b)| acc ^ (b as u64).rotate_left(i as u32 % 57))
    };

    let cp = unsafe { __cpuid(0) };
    let raw = now
        ^ (pid as u128).rotate_left(17)
        ^ (tid_hash as u128).rotate_right(13)
        ^ ((cp.eax as u128) << 16)
        ^ ((cp.edx as u128).rotate_left(5));

    let mut h = DefaultHasher::new();
    h.write_u128(!raw);
    let hash = h.finish();

    ((hash ^ (hash >> 32)) as u8)
        .rotate_left(((hash as u8) % 7) as u32)
        ^ 0xA9
}

/// Build the `foo!("…")` variants
fn exsingle(
    input: TokenStream,
    engine: KoenigEngine,
    decrypt_fn: TokenStream2,
) -> TokenStream {
    let plain = parse_literals(input).pop().unwrap_or_default();
    let seed = random_seed();
    let (ct, tag, frag, mask) = pulse(engine, plain.as_bytes(), seed);

    // turn them into literal streams
    let ct_bytes = ct.iter().map(|b| Literal::u8_unsuffixed(*b));
    let tag_bytes = tag.iter().map(|b| Literal::u8_unsuffixed(*b));
    let frag_rows = frag.iter().map(|blk| {
        let bytes = blk.iter().map(|b| Literal::u8_unsuffixed(*b));
        quote!([#(#bytes),*])
    });
    let mask_rows = mask.iter().map(|blk| {
        let bytes = blk.iter().map(|b| Literal::u8_unsuffixed(*b));
        quote!([#(#bytes),*])
    });

    let expanded = quote! {{
        let __ct: &[u8]        = &[#(#ct_bytes),*];
        let __tag: &[u8; 32]   = &[#(#tag_bytes),*];
        let __frag: [[u8; 8]; 4] = [#(#frag_rows),*];
        let __mask: [[u8; 8]; 4] = [#(#mask_rows),*];
        #decrypt_fn(__ct, __tag, __frag, __mask, #seed)
    }};
    expanded.into()
}

fn exmulti(
    input: TokenStream,
    engine: KoenigEngine,
    decrypt_fn: TokenStream2,
) -> TokenStream {
    let items = parse_literals(input);
    let base_seed = random_seed();

    let calls = items.into_iter().enumerate().map(|(i, item)| {
        let seed = base_seed ^ (i as u8);
        let (ct, tag, frag, mask) = pulse(engine, item.as_bytes(), seed);

        let ct_bytes = ct.iter().map(|b| Literal::u8_unsuffixed(*b));
        let tag_bytes = tag.iter().map(|b| Literal::u8_unsuffixed(*b));
        let frag_rows = frag.iter().map(|blk| {
            let bytes = blk.iter().map(|b| Literal::u8_unsuffixed(*b));
            quote!([#(#bytes),*])
        });
        let mask_rows = mask.iter().map(|blk| {
            let bytes = blk.iter().map(|b| Literal::u8_unsuffixed(*b));
            quote!([#(#bytes),*])
        });

        quote! {{
            let __ct: &[u8]        = &[#(#ct_bytes),*];
            let __tag: &[u8; 32]   = &[#(#tag_bytes),*];
            let __frag: [[u8; 8]; 4] = [#(#frag_rows),*];
            let __mask: [[u8; 8]; 4] = [#(#mask_rows),*];

            #decrypt_fn(__ct, __tag, __frag, __mask, #seed)
        }}
    });

    quote!([#(#calls),*]).into()
}

#[proc_macro]
pub fn jesko(input: TokenStream) -> TokenStream {
    exsingle(
        input,
        KoenigEngine::Jesko, quote! { ::koenig::engines::jesko::Jesko::decrypt },
    )
}

#[proc_macro]
pub fn jeskoex(input: TokenStream) -> TokenStream {
    exmulti(
        input,
        KoenigEngine::Jesko, quote! { ::koenig::engines::jesko::Jesko::decrypt },
    )
}

#[proc_macro]
pub fn absolut(input: TokenStream) -> TokenStream {
    exsingle(
        input,
        KoenigEngine::Absolut, quote! { ::koenig::engines::absolut::Absolut::decrypt },
    )
}

#[proc_macro]
pub fn absolutex(input: TokenStream) -> TokenStream {
    exmulti(
        input,
        KoenigEngine::Absolut, quote! { ::koenig::engines::absolut::Absolut::decrypt },
    )
}

#[proc_macro]
pub fn sadair(input: TokenStream) -> TokenStream {
    exsingle(
        input,
        KoenigEngine::Sadair, quote! { ::koenig::engines::sadair::Sadair::decrypt },
    )
}

#[proc_macro]
pub fn sadairex(input: TokenStream) -> TokenStream {
    exmulti(
        input,
        KoenigEngine::Sadair, quote! { ::koenig::engines::sadair::Sadair::decrypt },
    )
}

#[proc_macro]
pub fn gamera(input: TokenStream) -> TokenStream {
    exsingle(
        input,
        KoenigEngine::Gamera, quote! { ::koenig::engines::gamera::Gamera::decrypt },
    )
}

#[proc_macro]
pub fn gameraex(input: TokenStream) -> TokenStream {
    exmulti(
        input,
        KoenigEngine::Gamera, quote! { ::koenig::engines::gamera::Gamera::decrypt },
    )
}