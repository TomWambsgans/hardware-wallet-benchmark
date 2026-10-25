//! The device verifier as a C library: the Ledger app (`ledger/app`) supplies the proof stream and Keccak-f,
//! and calls [`leanvm_verify`].
//!
//! ```c
//! // The next `len` bytes of the proof stream into `out`: 0, or nonzero if the transport failed.
//! int32_t leanvm_read(uint8_t *out, uint32_t len);
//! // The proof has been read whole: 0 if nothing of the stream is left, nonzero otherwise.
//! int32_t leanvm_end(void);
//! // A Rust panic (a bug: the verifier rejects bad proofs with an error code, never a panic). Does not return.
//! void leanvm_panic(void);
//! // Keccak-f[1600] on the bit-interleaved state (ledger-app/src/crypto/keccak.c).
//! void keccak_permute(uint32_t s[50]);
//! ```

#![no_std]

use leanvm_ledger_verifier::transcript::{Piece, Source};
use leanvm_ledger_verifier::{Error, verify};

unsafe extern "C" {
    fn leanvm_read(out: *mut u8, len: u32) -> i32;
    fn leanvm_end() -> i32;
    fn leanvm_panic() -> !;
}

struct Stream;

impl Source for Stream {
    fn read(&mut self, _: Piece, out: &mut [u8]) -> Result<(), Error> {
        if out.is_empty() {
            return Ok(());
        }
        match unsafe { leanvm_read(out.as_mut_ptr(), out.len() as u32) } {
            0 => Ok(()),
            _ => Err(Error::Transport),
        }
    }

    fn finish(&mut self) -> Result<(), Error> {
        match unsafe { leanvm_end() } {
            0 => Ok(()),
            _ => Err(Error::StreamNotConsumed),
        }
    }
}

/// Verify the proof the stream carries for the compiled-in program on the 32-byte `public_input`: 0 if it is
/// accepted, else the [`Error`] code that rejected it.
///
/// # Safety
/// `public_input` points to 32 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leanvm_verify(public_input: *const u8) -> u32 {
    let mut statement = [0u8; 32];
    statement.copy_from_slice(unsafe { core::slice::from_raw_parts(public_input, 32) });
    match verify(&statement, &mut Stream) {
        Ok(()) => 0,
        Err(error) => error as u32,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { leanvm_panic() }
}
