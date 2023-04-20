use core::marker::PhantomData;

//
use zeroize::{Zeroize, ZeroizeOnDrop};

//
use aead::{
    consts::*,
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace, Error, KeyInit, KeySizeUser, Nonce,
};

//
use chacha20::{
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
    ChaCha12, ChaCha20, ChaCha8, XChaCha12, XChaCha20, XChaCha8,
};

///!!!!!!
const BLAKE3_CONTEXT: &str = "";

// pub type Tag = GenericArray<u8,U32>;

// pub type Key = GenericArray<u8,U32>;

// pub type Nonce = GenericArray<u8,U12>;

pub type ChaCha8Blake3 = ChaChaBlake3<ChaCha8, U12>;

pub type ChaCha12Blake3 = ChaChaBlake3<ChaCha12, U12>;

pub type ChaCha20Blake3 = ChaChaBlake3<ChaCha20, U12>;

pub type XChaCha8Blake3 = ChaChaBlake3<XChaCha8, U24>;

pub type XChaCha12Blake3 = ChaChaBlake3<XChaCha12, U24>;

pub type XChaCha20Blake3 = ChaChaBlake3<XChaCha20, U24>;


pub struct Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    cipher: C,
    mac_hasher: blake3::Hasher,
}

impl<C> Cipher<C>
where
    C: StreamCipher + StreamCipherSeek,
{
    fn new(mut cipher: C) -> Self {
        let mut mac_key = *blake3::Hasher::new_derive_key(BLAKE3_CONTEXT)
            .finalize()
            .as_bytes();

        cipher.apply_keystream(&mut mac_key);

        let mac_hasher = blake3::Hasher::new_keyed(&mac_key);

        mac_key.zeroize();

        cipher.seek(64);

        Self {
            cipher: cipher,
            mac_hasher: mac_hasher,
        }
    }

    //https://github.com/RustCrypto/AEADs/blob/master/chacha20poly1305/
    //https://github.com/RustCrypto/AEADs/blob/9bc7caee4f7387ee87fee6f4bd3856ad8a0855d0/chacha20poly1305/src/cipher.rs#L98
    fn auth_len(&mut self, associated_data: &[u8], buffer: &[u8]) -> Result<(), Error> {
        let associated_data_len: u64 = associated_data.len().try_into().map_err(|_| Error)?;

        let buffer_len: u64 = buffer.len().try_into().map_err(|_| Error)?;

        let mut block: GenericArray<u8, U16> = GenericArray::default();

        block[..8].copy_from_slice(&associated_data_len.to_le_bytes());

        block[8..].copy_from_slice(&buffer_len.to_le_bytes());

        self.mac_hasher.update(&block);

        Ok(())
    }

    //https://github.com/RustCrypto/AEADs/blob/master/chacha20poly1305/
    //https://github.com/RustCrypto/AEADs/blob/9bc7caee4f7387ee87fee6f4bd3856ad8a0855d0/chacha20poly1305/src/cipher.rs#L50
    fn encrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, U32>, Error> {
        self.cipher.apply_keystream(buffer);

        self.mac_hasher.update(associated_data).update(buffer);

        self.auth_len(associated_data, buffer)?;

        Ok(*GenericArray::from_slice(
            self.mac_hasher.finalize().as_bytes(),
        ))
    }

    fn decrypt_in_place_detached(
        mut self,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, U32>,
    ) -> Result<(), Error> {
        self.mac_hasher.update(associated_data).update(buffer);

        self.auth_len(associated_data, buffer)?;

        match self
            .mac_hasher
            .finalize()
            .as_bytes()
            .as_slice()
            .eq(tag.as_slice())
        {
            true => {
                self.cipher.apply_keystream(buffer);
                Ok(())
            }
            false => Err(Error),
        }
    }
}

//https://github.com/RustCrypto/AEADs/blob/9bc7caee4f7387ee87fee6f4bd3856ad8a0855d0/chacha20poly1305/src/lib.rs#L210
pub struct ChaChaBlake3<C, N: ArrayLength<u8> = U12> {
    key: GenericArray<u8, U32>,
    nonce_size: PhantomData<N>,
    cipher: PhantomData<C>,
}

impl<C, N> KeyInit for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    fn new(key: &GenericArray<u8, U32>) -> Self {
        Self {
            key: *key,
            nonce_size: PhantomData,
            cipher: PhantomData,
        }
    }
}

impl<C, N> KeySizeUser for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    type KeySize = U32;
}

impl<C, N> AeadCore for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    type NonceSize = N;
    type TagSize = U32;
    type CiphertextOverhead = U0;
}

impl<C, N> AeadInPlace for ChaChaBlake3<C, N>
where
    C: KeyIvInit<KeySize = U32, IvSize = N> + StreamCipher + StreamCipherSeek,
    N: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, U32>, Error> {
        Cipher::new(C::new(&self.key, nonce)).encrypt_in_place_detached(associated_data, buffer)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, U32>,
    ) -> Result<(), Error> {
        Cipher::new(C::new(&self.key, nonce)).decrypt_in_place_detached(
            associated_data,
            buffer,
            tag,
        )
    }
}

//https://github.com/RustCrypto/AEADs/blob/9bc7caee4f7387ee87fee6f4bd3856ad8a0855d0/chacha20poly1305/src/lib.rs#L280
impl<C, N> Clone for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            cipher: PhantomData,
            nonce_size: PhantomData,
        }
    }
}

//https://github.com/RustCrypto/AEADs/blob/9bc7caee4f7387ee87fee6f4bd3856ad8a0855d0/chacha20poly1305/src/lib.rs#L293
impl<C, N> Drop for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

//https://github.com/RustCrypto/AEADs/blob/9bc7caee4f7387ee87fee6f4bd3856ad8a0855d0/chacha20poly1305/src/lib.rs#L302
impl<C, N: ArrayLength<u8>> ZeroizeOnDrop for ChaChaBlake3<C, N> {}