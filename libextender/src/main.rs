// #![warn(missing_docs, rust_ 2018_idioms)]
#![allow(dead_code, unused_variables, unused_imports)]


use hex_literal::hex;
use hex as hex_encode;

mod mysha1;
use mysha1::{ExtendableSha1, Digest, ExtendableSha1Core};

use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};
use core::slice::from_ref;

use digest::core_api::{CoreWrapper, FixedOutputCore, Buffer};

use digest::crypto_common::{
    typenum::{IsLess, Le, NonZero, U256},
    Output,
};

enum PaddingType {
    LittleEndian64,
    BigEndian64,
}

struct HashType {
    name: &'static str,
    state_length: usize,
    little_endian: bool,
    block_size: usize,
    length_size: usize,
}

fn get_extended_string<T: FixedOutputCore>(secret_length: usize, original_data: &[u8], append_data: &[u8], pad: PaddingType) -> Vec<u8> where
    T::BlockSize: IsLess<U256>,
    Le<T::BlockSize, U256>: NonZero,
{
    let mut buffer = Buffer::<T>::default();
    let mut v = Vec::<u8>::new();

    // Add junk to get the hash into the right state
    buffer.digest_blocks(&b"A".repeat(secret_length), |b| {
        for block in b {
            v.extend_from_slice(block);
        }
    });

    // Add the original data (the data that's known to the user)
    buffer.digest_blocks(original_data, |b| {
        for block in b {
            v.extend_from_slice(block);
        }
    });

    // Figure out the length (in bits) of the whole hashed string
    let bit_len = 8 * (buffer.get_pos() as u64 + v.len() as u64);

    // Append the padding (which might overflow into a new block)
    match pad {
        PaddingType::LittleEndian64 => {
            buffer.len64_padding_le(bit_len, |b| {
                v.extend_from_slice(b);
            });
        },
        PaddingType::BigEndian64 => {
            buffer.len64_padding_be(bit_len, |b| {
                v.extend_from_slice(b);
            });
        },
    };

    // Remove the garbage data from the start
    v.drain(0..secret_length);

    // Add the appended data
    v.extend_from_slice(append_data);

    v
}

fn main() {
    // println!("Hello, world!");

    // // Sha1 stuff:
    // // Digest length = 160 bits (20 bytes)
    // // Big endian
    // // Block size = 512 bits (64 bytes)
    // // Length size = 64 bits (8 bytes)
    let secret = b"secret";
    let original_string = b"data";
    let append = b"append";
    let appended_string = hex!("64617461800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050617070656e64");

    // let mut hasher = ExtendableSha1::new();
    // hasher.update(secret);
    // hasher.update(original_string);
    // let original_hash = hasher.finalize();
    // println!("Original hash: {:x?}", hex_encode::encode(&original_hash[..]));

    // let mut hasher = ExtendableSha1::new();
    // hasher.update(secret);
    // hasher.update(appended_string);
    // let real_extended_hash = hasher.finalize();
    // println!("Extended hash (real): {:x?}", hex_encode::encode(&real_extended_hash[..]));

    // // (sha1 is big endian)
    // let mut rdr = Cursor::new(original_hash);
    // let i1 = rdr.read_u32::<BigEndian>().unwrap();
    // let i2 = rdr.read_u32::<BigEndian>().unwrap();
    // let i3 = rdr.read_u32::<BigEndian>().unwrap();
    // let i4 = rdr.read_u32::<BigEndian>().unwrap();
    // let i5 = rdr.read_u32::<BigEndian>().unwrap();

    println!("Extended: {}", hex_encode::encode(get_extended_string::<ExtendableSha1Core>(secret.len(), original_string, append, PaddingType::BigEndian64)));

    // buffer.len64_padding_be(bit_len, |b| {
    //     println!("Compress called: {:?}", b);
    //     compress(&mut h, from_ref(b))
    // });

    // let mut core: ExtendableSha1Core = Default::default();


    // core.set_state([i1, i2, i3, i4, i5], 1);
    // let mut hasher = CoreWrapper::from_core(core);

    // hasher.update(append);
    // let fake_extended_hash = hasher.finalize();

    // println!("Extended hash (fake): {:x?}", hex_encode::encode(&fake_extended_hash[..]));
    // println!();

    // pub fn set_state(&mut self, h: [u32; STATE_LEN], block_len: u64) {

    // // process input message
    // hasher.update(b"hello world");

    // // acquire hash digest in the form of GenericArray,
    // // which in this case is equivalent to [u8; 20]
    // let result = hasher.finalize();
    // assert_eq!(result[..], hex!("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"));

    // let mytest: ExtendableSha1Core = ExtendableSha1Core {
    //     h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
    //     block_len: 0,
    // };
}
