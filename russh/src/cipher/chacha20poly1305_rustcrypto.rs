// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! `chacha20-poly1305@openssh.com` with RustCrypto (the `rustcrypto` backend: no C).
//!
//! http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
//!
//! The 64-byte key is split into K_2 (first half: payload and Poly1305 key) and K_1 (second
//! half: packet length). Both use the original ChaCha20 with a 64-bit nonce, the big-endian
//! sequence number. The Poly1305 key is the first 32 bytes of K_2's keystream block 0; the
//! payload is encrypted from block 1; the tag covers the encrypted length and payload.

use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use subtle::ConstantTimeEq;

use super::super::Error;
use crate::mac::MacAlgorithm;

pub const KEY_LEN: usize = 64;
pub const TAG_LEN: usize = 16;

pub struct SshChacha20Poly1305Cipher {}

impl super::Cipher for SshChacha20Poly1305Cipher {
    fn key_len(&self) -> usize {
        KEY_LEN
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        _: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        Box::new(OpeningKey(Keys::new(k)))
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        _: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        Box::new(SealingKey(Keys::new(k)))
    }
}

struct Keys {
    /// K_1: encrypts the packet length.
    length: [u8; 32],
    /// K_2: encrypts the payload and derives the Poly1305 key.
    main: [u8; 32],
}

impl Keys {
    fn new(k: &[u8]) -> Self {
        let mut main = [0; 32];
        let mut length = [0; 32];
        #[allow(clippy::indexing_slicing)] // key_len() is 64
        {
            main.copy_from_slice(&k[..32]);
            length.copy_from_slice(&k[32..64]);
        }
        Self { length, main }
    }

    fn stream(key: &[u8; 32], sequence_number: u32) -> ChaCha20Legacy {
        let nonce = u64::from(sequence_number).to_be_bytes();
        ChaCha20Legacy::new(key.into(), &nonce.into())
    }

    /// The payload stream (positioned at block 1) and the Poly1305 key (block 0).
    fn payload_stream(&self, sequence_number: u32) -> (ChaCha20Legacy, [u8; 32]) {
        let mut stream = Self::stream(&self.main, sequence_number);
        let mut poly_key = [0; 32];
        stream.apply_keystream(&mut poly_key);
        stream.seek(64u64);
        (stream, poly_key)
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.length = [0; 32];
        self.main = [0; 32];
    }
}

pub struct OpeningKey(Keys);

pub struct SealingKey(Keys);

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &self,
        sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        let mut length = [0; 4];
        #[allow(clippy::indexing_slicing)] // always 4 bytes
        length.copy_from_slice(&encrypted_packet_length[..4]);
        Keys::stream(&self.0.length, sequence_number).apply_keystream(&mut length);
        length
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(
        &mut self,
        sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let ciphertext_len = ciphertext_and_tag
            .len()
            .checked_sub(TAG_LEN)
            .filter(|len| *len >= super::PACKET_LENGTH_LEN)
            .ok_or(Error::DecryptionError)?;
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_len);
        let (mut stream, poly_key) = self.0.payload_stream(sequence_number);
        // Verify before decrypting: the buffer stays unmodified if the tag is wrong.
        let expected = Poly1305::new(&poly_key.into()).compute_unpadded(ciphertext);
        if !bool::from(expected.as_slice().ct_eq(tag)) {
            return Err(Error::DecryptionError);
        }
        #[allow(clippy::indexing_slicing)] // length checked above
        let payload = &mut ciphertext[super::PACKET_LENGTH_LEN..];
        stream.apply_keystream(payload);
        Ok(payload)
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 8;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN - payload.len() - super::PADDING_LENGTH_LEN
        } else {
            block_size - ((super::PADDING_LENGTH_LEN + payload.len()) % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    // As explained in "SSH via CTR mode with stateful decryption" in
    // https://openvpn.net/papers/ssh-security.pdf, the padding doesn't need to
    // be random because we're doing stateful counter-mode encryption. Use
    // fixed padding to avoid PRNG overhead.
    fn fill_padding(&self, padding_out: &mut [u8]) {
        for padding_byte in padding_out {
            *padding_byte = 0;
        }
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(
        &mut self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag: &mut [u8],
    ) {
        let (length, payload) = plaintext_in_ciphertext_out.split_at_mut(super::PACKET_LENGTH_LEN);
        Keys::stream(&self.0.length, sequence_number).apply_keystream(length);
        let (mut stream, poly_key) = self.0.payload_stream(sequence_number);
        stream.apply_keystream(payload);
        let computed = Poly1305::new(&poly_key.into()).compute_unpadded(plaintext_in_ciphertext_out);
        tag.copy_from_slice(computed.as_slice());
    }
}
