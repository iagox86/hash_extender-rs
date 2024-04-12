pub use digest::{self, Digest};
use core::{fmt, slice::from_ref};
use digest::{
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, Reset, UpdateCore,
    },
    typenum::{Unsigned, U20, U64},
    HashMarker, Output,
};

use sha1::compress;

const STATE_LEN: usize = 5;

/// Core SHA-1 hasher state.
#[derive(Clone)]
pub struct ExtendableSha1Core {
    h: [u32; STATE_LEN],
    block_len: u64,
}

impl HashMarker for ExtendableSha1Core {}

impl BlockSizeUser for ExtendableSha1Core {
    type BlockSize = U64;
}

impl BufferKindUser for ExtendableSha1Core {
    type BufferKind = Eager;
}

impl OutputSizeUser for ExtendableSha1Core {
    type OutputSize = U20;
}

impl UpdateCore for ExtendableSha1Core {
    #[inline]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.block_len += blocks.len() as u64;
        compress(&mut self.h, blocks);
    }
}

impl FixedOutputCore for ExtendableSha1Core {
    #[inline]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bs = Self::BlockSize::U64;

        // Length in bits
        let bit_len = 8 * (buffer.get_pos() as u64 + bs * self.block_len);

        let mut h = self.h;
        buffer.len64_padding_be(bit_len, |b| {
            println!("Compress called: {:?}", b);
            compress(&mut h, from_ref(b))
        });
        for (chunk, v) in out.chunks_exact_mut(4).zip(h.iter()) {
            chunk.copy_from_slice(&v.to_be_bytes());
        }
    }
}

impl Default for ExtendableSha1Core {
    #[inline]
    fn default() -> Self {
        Self {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            block_len: 0,
        }
    }
}

impl Reset for ExtendableSha1Core {
    #[inline]
    fn reset(&mut self) {
        *self = Default::default();
    }
}

impl AlgorithmName for ExtendableSha1Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExtendableSha1")
    }
}

impl fmt::Debug for ExtendableSha1Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("ExtendableSha1Core {{ {:x} {:x} {:x} {:x} {:x} }}", self.h[0], self.h[1], self.h[2], self.h[3], self.h[4])) // TODO Clean this up
    }
}

impl ExtendableSha1Core {
    // block_len = number of blocks processed so far
    pub fn new_with_state(h: [u32; STATE_LEN], block_len: u64) -> ExtendableSha1Core {
        let core = Self {
            h: h,
            block_len: block_len,
        };

        // CoreWrapper::from_core(core)
        core
    }

    pub fn set_state(&mut self, h: [u32; STATE_LEN], block_len: u64) {
        self.h = h;
        self.block_len = block_len;
    }
}

/// SHA-1 hasher state.
pub type ExtendableSha1 = CoreWrapper<ExtendableSha1Core>;
