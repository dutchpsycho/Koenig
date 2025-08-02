#![feature(asm)]
#![doc = r#"
# Gamera Engine

**Gamera** is a compact, ultra-fast string obfuscation engine designed for **low-overhead** and **maximum runtime stealth**.
It applies a custom **XOR-based transformation** using per-byte mutation, along with inline **x86_64 assembly junk instructions**, decoy logic, and anti-static-analysis noise.

> **WARNING:** This engine is *not cryptographically secure*. It is meant for **light obfuscation** of non-sensitive strings (like feature flags, toggles, or bait).

**Use cases:**
- Cheats or implants that require tiny, fast, reversible string obfuscation
- Debugger & EDR/AV confusion via non-standard, non-crypto-looking logic
- Inline obfuscation with fake control flow and assembly junk

Implements the [`Encryptor`](crate::Encryptor) trait.
"#]

use crate::Encryptor;
use std::arch::asm;

/// Gamera is a reversible XOR-based transformation engine with embedded inline x86_64 assembly junk,
/// decoy control flow, and bait instructions to confuse static disassemblers and AV heuristics.
///
/// **Use for obfuscation only**, not encryption. This engine is intentionally insecure
/// and optimized solely for runtime speed and signature confusion.
pub struct Gamera;

impl Gamera {
    /// Applies the reversible transformation on the input buffer using a rotating seed.
    ///
    /// This routine includes:
    /// - XOR logic based on the `seed` and byte index
    /// - Fake control flow (call/jmp trampolines)
    /// - MMX/FPU noise (e.g., `fldpi`, `emms`)
    /// - Anti-debug/timing bait (e.g., `rdtsc`)
    ///
    /// # Arguments
    /// - `input`: Input byte slice to transform
    /// - `seed`: 8-bit entropy seed that drives XOR masking
    ///
    /// # Returns
    /// - `Vec<u8>`: Transformed (obfuscated or restored) output
    ///
    /// # Safety
    /// Unsafe inline assembly is used for anti-analysis behavior.
    #[inline(always)]
    fn transform(input: &[u8], seed: u8) -> Vec<u8> {
        let mut out = vec![0u8; input.len()];

        for i in 0..input.len() {
            unsafe {
                let mut byte: u8 = 0;
                let in_ptr = input.as_ptr().add(i);
                let out_ptr = out.as_mut_ptr().add(i);
                let idx = i as u8;

                asm!(
                // FPU/stack junk
                "finit",
                "fldpi",
                "fldz",
                "faddp st(1), st(0)",
                "fstp qword ptr [rsp]",

                // Time-based bait
                "rdtsc",
                "shl rax, 1",
                "xor rax, rdx",

                // Fake trampoline
                "call 6f", "jmp 7f",
                "6:", "pop r10", "add r10, 0x10", "jmp 8f",
                "7:", "nop", "jmp 9f",
                "8:", "xor r11d, r11d",
                "9:",

                // CFG noise
                "cmp r10, r10", "je 20f", "jmp 21f",
                "20:", "lea rax, [rax + 0]", "nop", "jmp 22f",
                "21:", "mov rbx, rbx", "jmp 22f",
                "22:",

                // Load + XOR logic
                "movzx eax, byte ptr [{in_ptr}]",
                "mov cl, {seed}",
                "mov dl, {idx}",
                "xor cl, dl",
                "ror cl, 3",
                "xor cl, 0x3C",
                "imul edx, edx, 0xB",
                "add cl, dl",

                // Tracer noise
                "xor r15d, r15d",
                "cmp r15d, 1", "jne 13f", "jmp 14f",
                "13:", "nop", "14:",

                // Final XOR
                "xor al, cl",

                // MMX bait
                "movq mm2, mm3",
                "pxor mm2, mm2",
                "emms",

                // Store output
                "mov byte ptr [{out_ptr}], al",

                in_ptr = in(reg) in_ptr,
                out_ptr = in(reg) out_ptr,
                seed = in(reg_byte) seed,
                idx = in(reg_byte) idx,
                out("rax") _,
                out("rcx") _,
                out("rdx") _,
                out("r10") _,
                out("r11") _,
                out("r15d") _,
                );
            }
        }

        out
    }

    /// Returns 4×8-byte zeroed fragments to comply with the `Encryptor` trait.
    ///
    /// This engine doesn't use real fragment masking.
    #[inline(always)]
    fn dummy_fragments() -> ([[u8; 8]; 4], [[u8; 8]; 4]) {
        ([[0u8; 8]; 4], [[0u8; 8]; 4])
    }

    /// Returns a 32-byte zeroed MAC tag placeholder.
    ///
    /// No integrity/authentication is provided.
    #[inline(always)]
    fn dummy_tag() -> [u8; 32] {
        [0u8; 32]
    }
}

impl Encryptor for Gamera {
    /// Applies the Gamera transformation to the plaintext.
    ///
    /// # Arguments
    /// - `plain`: Plaintext to obfuscate
    /// - `seed`: Transformation seed (must match for decryption)
    ///
    /// # Returns
    /// - `(ciphertext, tag, frag, mask)` — only ciphertext is meaningful
    #[inline(always)]
    fn encrypt(plain: &[u8], seed: u8) -> (Vec<u8>, [u8; 32], [[u8; 8]; 4], [[u8; 8]; 4]) {
        let ct = Self::transform(plain, seed);
        let (frag, mask) = Self::dummy_fragments();
        (ct, Self::dummy_tag(), frag, mask)
    }

    /// Reverses the Gamera transformation using the same seed.
    ///
    /// # Arguments
    /// - `ct`: Obfuscated ciphertext
    /// - `_tag`, `_frag`, `_mask`: Ignored (placeholder values)
    /// - `seed`: The same seed used in `encrypt`
    ///
    /// # Returns
    /// - Decrypted UTF-8 `String`
    ///
    /// # Panics
    /// - If output is not valid UTF-8
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