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

//! `aes128-gcm@openssh.com` / `aes256-gcm@openssh.com` with RustCrypto (the `rustcrypto`
//! backend: no C). RFC 5647: the packet length is sent unencrypted as associated data; the
//! 12-byte nonce starts at the derived IV and is incremented after every packet.

use aes_gcm::aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use rand_core::Rng;

use super::super::Error;
use crate::keys::key::safe_rng;
use crate::mac::MacAlgorithm;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Which AES-GCM.
pub enum Algorithm {
    Aes128,
    Aes256,
}

pub(crate) static ALGORITHM_AES_128_GCM: Algorithm = Algorithm::Aes128;
pub(crate) static ALGORITHM_AES_256_GCM: Algorithm = Algorithm::Aes256;

pub struct GcmCipher(pub(crate) &'static Algorithm);

enum Aead {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl Aead {
    #[allow(clippy::unwrap_used)] // key_len() is the cipher's key length
    fn new(algorithm: &Algorithm, k: &[u8]) -> Self {
        match algorithm {
            Algorithm::Aes128 => Aead::Aes128(Box::new(Aes128Gcm::new_from_slice(k).unwrap())),
            Algorithm::Aes256 => Aead::Aes256(Box::new(Aes256Gcm::new_from_slice(k).unwrap())),
        }
    }

    fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buffer: &mut [u8]) -> [u8; TAG_LEN] {
        let nonce = Nonce::from(*nonce);
        #[allow(clippy::unwrap_used)] // only fails for messages over 64 GiB
        let tag = match self {
            Aead::Aes128(a) => a.encrypt_inout_detached(&nonce, aad, buffer.into()).unwrap(),
            Aead::Aes256(a) => a.encrypt_inout_detached(&nonce, aad, buffer.into()).unwrap(),
        };
        tag.into()
    }

    fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buffer: &mut [u8], tag: &[u8]) -> Result<(), Error> {
        let nonce = Nonce::from(*nonce);
        let tag = Tag::try_from(tag).map_err(|_| Error::DecryptionError)?;
        match self {
            Aead::Aes128(a) => a.decrypt_inout_detached(&nonce, aad, buffer.into(), &tag),
            Aead::Aes256(a) => a.decrypt_inout_detached(&nonce, aad, buffer.into(), &tag),
        }
        .map_err(|_| Error::DecryptionError)
    }
}

/// The per-packet nonce: starts at the IV, incremented (as a 96-bit big-endian number) after
/// each packet.
struct Nonces([u8; NONCE_LEN]);

impl Nonces {
    fn next(&mut self) -> [u8; NONCE_LEN] {
        let current = self.0;
        let mut carry = 1u16;
        for byte in self.0.iter_mut().rev() {
            let n = u16::from(*byte) + carry;
            *byte = n as u8;
            carry = n >> 8;
        }
        current
    }
}

impl super::Cipher for GcmCipher {
    fn key_len(&self) -> usize {
        match self.0 {
            Algorithm::Aes128 => 16,
            Algorithm::Aes256 => 32,
        }
    }

    fn nonce_len(&self) -> usize {
        NONCE_LEN
    }

    fn make_opening_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::OpeningKey + Send> {
        #[allow(clippy::unwrap_used)] // nonce_len() is 12
        Box::new(OpeningKey { aead: Aead::new(self.0, k), nonces: Nonces(n.try_into().unwrap()) })
    }

    fn make_sealing_key(
        &self,
        k: &[u8],
        n: &[u8],
        _: &[u8],
        _: &dyn MacAlgorithm,
    ) -> Box<dyn super::SealingKey + Send> {
        #[allow(clippy::unwrap_used)] // nonce_len() is 12
        Box::new(SealingKey { aead: Aead::new(self.0, k), nonces: Nonces(n.try_into().unwrap()) })
    }
}

pub struct OpeningKey {
    aead: Aead,
    nonces: Nonces,
}

pub struct SealingKey {
    aead: Aead,
    nonces: Nonces,
}

impl super::OpeningKey for OpeningKey {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        encrypted_packet_length: &[u8],
    ) -> [u8; 4] {
        // The packet length is sent unencrypted.
        #[allow(clippy::unwrap_used)] // always 4 bytes
        encrypted_packet_length.try_into().unwrap()
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(
        &mut self,
        _sequence_number: u32,
        ciphertext_and_tag: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let ciphertext_len = ciphertext_and_tag
            .len()
            .checked_sub(TAG_LEN)
            .filter(|len| *len >= super::PACKET_LENGTH_LEN)
            .ok_or(Error::DecryptionError)?;
        let (ciphertext, tag) = ciphertext_and_tag.split_at_mut(ciphertext_len);
        let (packet_length, payload) = ciphertext.split_at_mut(super::PACKET_LENGTH_LEN);
        let nonce = self.nonces.next();
        self.aead.open(&nonce, packet_length, payload, tag)?;
        Ok(payload)
    }
}

impl super::SealingKey for SealingKey {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
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

    fn fill_padding(&self, padding_out: &mut [u8]) {
        safe_rng().fill_bytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(
        &mut self,
        _sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag: &mut [u8],
    ) {
        let (packet_length, payload) = plaintext_in_ciphertext_out.split_at_mut(super::PACKET_LENGTH_LEN);
        let nonce = self.nonces.next();
        tag.copy_from_slice(&self.aead.seal(&nonce, packet_length, payload));
    }
}
