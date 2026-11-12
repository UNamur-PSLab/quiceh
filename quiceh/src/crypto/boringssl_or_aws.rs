use super::*;

use std::convert::TryFrom;
use std::mem::MaybeUninit;

#[cfg(feature = "ocb3")]
use ocb3::{AEctx, DecryptIO, EncryptIO, PlainText};

use libc::c_int;
use libc::c_uint;
use libc::c_void;

// NOTE: This structure is copied from <openssl/aead.h> in order to be able to
// statically allocate it. While it is not often modified upstream, it needs to
// be kept in sync.
#[repr(C)]
struct EVP_AEAD_CTX {
    aead: libc::uintptr_t,
    opaque: [u8; 580],
    alignment: u64,
    tag_len: u8,
}

#[derive(Clone)]
#[repr(C)]
pub(crate) struct AES_KEY {
    rd_key: [u32; 4 * (14 + 1)],
    rounds: c_int,
}

impl Algorithm {
    fn get_evp_aead(self) -> *const EVP_AEAD {
        match self {
            Algorithm::AES128_GCM => unsafe { EVP_aead_aes_128_gcm() },
            Algorithm::AES256_GCM => unsafe { EVP_aead_aes_256_gcm() },
            Algorithm::ChaCha20_Poly1305 => unsafe {
                EVP_aead_chacha20_poly1305()
            },
            Algorithm::OCB3_AES128 | Algorithm::OCB3_AES256 => {
                unreachable!("OCB3 has no EVP AEAD")
            },
        }
    }
}

fn make_aead_ctx(alg: Algorithm, key: &[u8]) -> Result<EVP_AEAD_CTX> {
    let mut ctx = MaybeUninit::uninit();
    let ctx = unsafe {
        let aead = alg.get_evp_aead();

        let rc = EVP_AEAD_CTX_init(
            ctx.as_mut_ptr(),
            aead,
            key.as_ptr(),
            alg.key_len(),
            alg.tag_len(),
            std::ptr::null_mut(),
        );

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        ctx.assume_init()
    };

    Ok(ctx)
}

pub(crate) struct PacketKey {
    alg: Algorithm,
    
    ctx: Option<EVP_AEAD_CTX>,

    #[cfg(feature = "ocb3")]
    ocb3_ctx: Option<AEctx>,

    nonce: Vec<u8>,
}

impl PacketKey {
    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, _enc: u32,
    ) -> Result<Self> {
        #[cfg(not(feature = "ocb3"))]
        if matches!(alg, Algorithm::OCB3_AES128 | Algorithm::OCB3_AES256) {
            log::error!("OCB3 feature is not enabled!");
            return Err(Error::CryptoFail);
        }
        match alg {
            Algorithm::AES128_GCM | Algorithm::AES256_GCM | Algorithm::ChaCha20_Poly1305 => {
                Ok(Self {
                    alg,
                    ctx: Some(make_aead_ctx(alg, &key)?),
                    #[cfg(feature = "ocb3")]
                    ocb3_ctx: None,
                    nonce: iv,
                })
            },
            #[cfg(feature = "ocb3")]
            Algorithm::OCB3_AES128 => {
                Ok(Self {
                    alg,
                    ctx: None,
                    ocb3_ctx: Some(AEctx::new(&key)),
                    nonce: iv,
                })
            },
            _ => unimplemented!()
        }
    }

    pub fn from_secret(aead: Algorithm, secret: &[u8], enc: u32) -> Result<Self> {
        let key_len = aead.key_len();
        let nonce_len = aead.nonce_len();

        let mut key = vec![0; key_len];
        let mut iv = vec![0; nonce_len];

        derive_pkt_key(aead, secret, &mut key)?;
        derive_pkt_iv(aead, secret, &mut iv)?;

        let pkt_key = Self::new(aead, key, iv, enc)?;

        Ok(pkt_key)
    }

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        let tag_len = self.alg.tag_len();

        let mut out_len = match buf.len().checked_sub(tag_len) {
            Some(n) => n,
            None => return Err(Error::CryptoFail),
        };

        let max_out_len = out_len;

        let nonce = make_nonce(&self.nonce, counter);

        match self.alg {
            Algorithm::AES128_GCM | Algorithm::AES256_GCM | Algorithm::ChaCha20_Poly1305 => {
                let rc = unsafe {
                    EVP_AEAD_CTX_open(
                        self.ctx.as_ref().unwrap(), // ctx
                        buf.as_mut_ptr(),   // out
                        &mut out_len,       // out_len
                        max_out_len,        // max_out_len
                        nonce[..].as_ptr(), // nonce
                        nonce.len(),        // nonce_len
                        buf.as_ptr(),       // inp
                        buf.len(),          // in_len
                        ad.as_ptr(),        // ad
                        ad.len(),           // ad_len
                    )
                };

                if rc != 1 {
                    return Err(Error::CryptoFail);
                }
                Ok(out_len)
            },
            #[cfg(feature = "ocb3")]
            Algorithm::OCB3_AES128 => {
                match &self.ocb3_ctx {
                    Some(ctx) => {
                        ctx.ae_decrypt(DecryptIO::InPlace(buf), &nonce, ad).map_err(|_| Error::CryptoFail)?;
                        Ok(out_len)
                    },
                    None => return Err(Error::CryptoFail),
                }
            },
            _ => {
                log::error!("Unsupported algorithm {:?}", self.alg);
                Err(Error::CryptoFail)
            }
        }

    }

    pub fn open_with_u64_counter_into(
        &self, counter: u64, ad: &[u8], buf: &[u8], into: &mut [u8],
    ) -> Result<usize> {
        if cfg!(feature = "fuzzing") {
            return Ok(buf.len());
        }
        let tag_len = self.alg.tag_len();

        let mut out_len = match buf.len().checked_sub(tag_len) {
            Some(n) => n,
            None => return Err(Error::CryptoFail),
        };
        let max_out_len = out_len;

        if into.len() < max_out_len {
            return Err(Error::CryptoFail);
        }

        let nonce = make_nonce(&self.nonce, counter);

        match self.alg {
            Algorithm::AES128_GCM | Algorithm::AES256_GCM | Algorithm::ChaCha20_Poly1305 => {
                let rc = unsafe {
                    EVP_AEAD_CTX_open(
                        self.ctx.as_ref().unwrap(), // ctx
                        into.as_mut_ptr(),  // out
                        &mut out_len,       // out_len
                        max_out_len,        // max_out_len
                        nonce[..].as_ptr(), // nonce
                        nonce.len(),        // nonce_len
                        buf.as_ptr(),       // inp
                        buf.len(),          // in_len
                        ad.as_ptr(),        // ad
                        ad.len(),           // ad_len
                    )
                };

                if rc != 1 {
                    return Err(Error::CryptoFail);
                }

                Ok(out_len)
            },
            #[cfg(feature = "ocb3")]
            Algorithm::OCB3_AES128 => {
                match &self.ocb3_ctx {
                    Some(ctx) => {
                        ctx.ae_decrypt(DecryptIO::OutOfPlace { in_ct: buf, out_pt: into }, 
                            &nonce,
                            ad).map_err(|_| Error::CryptoFail)?;
                        Ok(out_len)
                    },
                    None => Err(Error::CryptoFail)
                }
            },
            _ => {
                log::error!("Unsupported algorithm {:?}", self.alg);
                Err(Error::CryptoFail)
            }
        }
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], head: SealPiece,
        tail: SealPiece,
    ) -> Result<usize> {
        let head_len = head.len();
        let tail_len = tail.len();
        let tag_len = self.alg.tag_len();

        if cfg!(feature = "fuzzing") {
            if let SealPiece::OutOfPlace(v) = head {
                buf[..head_len].copy_from_slice(v);
            }

            if let SealPiece::OutOfPlace(v) = tail {
                buf[head_len..head_len + tail_len].copy_from_slice(v);
            }

            return Ok(head_len + tail_len);
        }

        // The destination covers the whole payload followed by the tag,
        // whichever AEAD ends up writing it.
        if head_len + tail_len + tag_len > buf.len() {
            debug!("Buffer too small");
            return Err(Error::CryptoFail);
        }

        let nonce = make_nonce(&self.nonce, counter);

        match self.alg {
            Algorithm::AES128_GCM | Algorithm::AES256_GCM | Algorithm::ChaCha20_Poly1305 => {
                let mut out_tag_len = tag_len + tail_len;

                // EVP_AEAD_CTX_seal_scatter encrypts inp into out and
                // extra_in into out_tag, so an in-place piece is simply
                // read back from the destination at its own offset.
                let (in_ptr, extra_in_ptr) = unsafe {
                    let dst = buf.as_mut_ptr();

                    let in_ptr = match head {
                        SealPiece::OutOfPlace(v) => v.as_ptr(),
                        SealPiece::InPlace { .. } => dst,
                    };

                    let extra_in_ptr = if tail_len == 0 {
                        std::ptr::null()
                    } else {
                        match tail {
                            SealPiece::OutOfPlace(v) => v.as_ptr(),
                            SealPiece::InPlace { .. } => dst.add(head_len),
                        }
                    };

                    (in_ptr, extra_in_ptr)
                };

                let rc = unsafe {
                    let out_tag_mut_ptr = buf.as_mut_ptr().add(head_len);
                    EVP_AEAD_CTX_seal_scatter(
                        self.ctx.as_ref().unwrap(),              // ctx
                        buf.as_mut_ptr(),       // out
                        out_tag_mut_ptr,        // out_tag
                        &mut out_tag_len,       // out_tag_len
                        tag_len + tail_len,     // max_out_tag_len
                        nonce[..].as_ptr(),     // nonce
                        nonce.len(),            // nonce_len
                        in_ptr,                 // inp
                        head_len,               // in_len
                        extra_in_ptr,           // extra_in
                        tail_len,               // extra_in_len
                        ad.as_ptr(),            // ad
                        ad.len(),               // ad_len
                    )
                };
                if rc != 1 {
                    debug!("seal_scatter returned -1");
                    return Err(Error::CryptoFail);
                }

                Ok(head_len + out_tag_len)
            },
            #[cfg(feature = "ocb3")]
            Algorithm::OCB3_AES128 => {
                // ocb3 sizes the plaintext from the slices it is handed and
                // bounds the destination against `out.len()`, so it is given
                // exactly the payload followed by the tag slot.
                let payload = &mut buf[..head_len + tail_len + tag_len];

                let ctx = match &self.ocb3_ctx {
                    Some(ctx) => ctx,
                    None => return Err(Error::CryptoFail),
                };

                let head_src = match &head {
                    SealPiece::OutOfPlace(v) if !v.is_empty() => Some(*v),
                    _ => None,
                };

                let tail_src = match &tail {
                    SealPiece::OutOfPlace(v) if !v.is_empty() => Some(*v),
                    _ => None,
                };

                // A piece that is not read from outside still contributes to
                // the plaintext when it is non-empty, in which case it
                // overlaps the destination.
                let head_pinned = head_src.is_none() && head_len > 0;
                let tail_pinned = tail_src.is_none() && tail_len > 0;

                let result = if head_pinned || tail_pinned {
                    if head_src.is_some() || tail_src.is_some() {
                        // One piece sits inside the destination while the
                        // other sits outside it. ocb3 takes the plaintext
                        // pieces as shared slices and the destination as a
                        // mutable one, so the overlap has no safe spelling;
                        // supporting it needs an ocb3 API that reads a head
                        // from outside while encrypting the rest in place.
                        log::error!(
                            "ocb3 cannot seal {} in-place bytes next to {} bytes read from outside the destination",
                            if head_pinned { head_len } else { tail_len },
                            if head_pinned { tail_len } else { head_len },
                        );

                        return Err(Error::CryptoFail);
                    }

                    ctx.ae_encrypt(EncryptIO::InPlace(payload), &nonce, ad)
                } else if let (Some(h), Some(t)) = (head_src, tail_src) {
                    ctx.ae_encrypt(
                        EncryptIO::OutOfPlace {
                            in_pt: PlainText::Scattered(h, t),
                            out: payload,
                        },
                        &nonce,
                        ad,
                    )
                } else if let Some(h) = head_src {
                    ctx.ae_encrypt(
                        EncryptIO::OutOfPlace {
                            in_pt: PlainText::Contiguous(h),
                            out: payload,
                        },
                        &nonce,
                        ad,
                    )
                } else if let Some(t) = tail_src {
                    ctx.ae_encrypt(
                        EncryptIO::OutOfPlace {
                            in_pt: PlainText::Contiguous(t),
                            out: payload,
                        },
                        &nonce,
                        ad,
                    )
                } else {
                    ctx.ae_encrypt(EncryptIO::InPlace(payload), &nonce, ad)
                };

                result.map_err(|_| Error::CryptoFail)?;

                Ok(head_len + tail_len + tag_len)
            },
            _ => {
                log::error!("Unsupported algorithm {:?}", self.alg);
                Err(Error::CryptoFail)
            }
        }
    }
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum HeaderProtectionKey {
    Aes(AES_KEY),

    ChaCha(Vec<u8>),
}

impl HeaderProtectionKey {
    pub fn new(alg: Algorithm, hp_key: Vec<u8>) -> Result<Self> {
        match alg {
            Algorithm::AES128_GCM
            | Algorithm::AES256_GCM
            | Algorithm::OCB3_AES128 => unsafe {
                let key_len_bits = alg.key_len() as u32 * 8;

                let mut aes_key = MaybeUninit::<AES_KEY>::uninit();

                let rc = AES_set_encrypt_key(
                    hp_key.as_ptr(),
                    key_len_bits,
                    aes_key.as_mut_ptr(),
                );

                if rc != 0 {
                    return Err(Error::CryptoFail);
                }

                let aes_key = aes_key.assume_init();
                Ok(Self::Aes(aes_key))
            },

            Algorithm::OCB3_AES256 => {
                log::error!("AES256 is not supported for our OCB3 provider");
                Err(Error::CryptoFail)
            },

            Algorithm::ChaCha20_Poly1305 => Ok(Self::ChaCha(hp_key)),
        }
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<HeaderProtectionMask> {
        match self {
            Self::Aes(aes_key) => {
                let mut block = [0_u8; 16];

                unsafe {
                    AES_ecb_encrypt(
                        sample.as_ptr(),
                        block.as_mut_ptr(),
                        aes_key as _,
                        1,
                    )
                };

                // Downsize the encrypted block to the size of the header
                // protection mask.
                //
                // The length of the slice will always match the size of
                // `HeaderProtectionMask` so the `unwrap()` is safe.
                let new_mask =
                    HeaderProtectionMask::try_from(&block[..HP_MASK_LEN])
                        .unwrap();
                Ok(new_mask)
            },

            Self::ChaCha(key) => {
                const PLAINTEXT: &[u8; HP_MASK_LEN] = &[0_u8; HP_MASK_LEN];

                let mut new_mask = HeaderProtectionMask::default();

                let counter = u32::from_le_bytes([
                    sample[0], sample[1], sample[2], sample[3],
                ]);

                unsafe {
                    CRYPTO_chacha_20(
                        new_mask.as_mut_ptr(),
                        PLAINTEXT.as_ptr(),
                        PLAINTEXT.len(),
                        key.as_ptr(),
                        sample[size_of::<u32>()..].as_ptr(),
                        counter,
                    );
                };

                Ok(new_mask)
            },
        }
    }
}

pub(crate) fn hkdf_extract(
    alg: Algorithm, out: &mut [u8], secret: &[u8], salt: &[u8],
) -> Result<()> {
    let mut out_len = out.len();

    let rc = unsafe {
        HKDF_extract(
            out.as_mut_ptr(),
            &mut out_len,
            alg.get_evp_digest(),
            secret.as_ptr(),
            secret.len(),
            salt.as_ptr(),
            salt.len(),
        )
    };

    if rc != 1 {
        return Err(Error::CryptoFail);
    }

    Ok(())
}

pub(crate) fn hkdf_expand(
    alg: Algorithm, out: &mut [u8], secret: &[u8], info: &[u8],
) -> Result<()> {
    let rc = unsafe {
        HKDF_expand(
            out.as_mut_ptr(),
            out.len(),
            alg.get_evp_digest(),
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        )
    };

    if rc != 1 {
        return Err(Error::CryptoFail);
    }

    Ok(())
}
#[cfg(all(feature = "aws-lc", not(feature = "boringssl-boring-crate")))]
use aws_lc_sys as sys;
#[cfg(feature = "boringssl-boring-crate")]
use boring_sys as sys;

#[inline]
#[allow(non_snake_case)]
unsafe fn EVP_aead_aes_128_gcm() -> *const EVP_AEAD {
    sys::EVP_aead_aes_128_gcm() as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn EVP_aead_aes_256_gcm() -> *const EVP_AEAD {
    sys::EVP_aead_aes_256_gcm() as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn EVP_aead_chacha20_poly1305() -> *const EVP_AEAD {
    sys::EVP_aead_chacha20_poly1305() as _
}

// HKDF
#[inline]
#[allow(non_snake_case)]
unsafe fn HKDF_extract(
    out_key: *mut u8, out_len: *mut usize, digest: *const EVP_MD,
    secret: *const u8, secret_len: usize, salt: *const u8, salt_len: usize,
) -> c_int {
    sys::HKDF_extract(
        out_key as _,
        out_len as _,
        digest as _,
        secret as _,
        secret_len as _,
        salt as _,
        salt_len as _,
    ) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn HKDF_expand(
    out_key: *mut u8, out_len: usize, digest: *const EVP_MD, prk: *const u8,
    prk_len: usize, info: *const u8, info_len: usize,
) -> c_int {
    sys::HKDF_expand(
        out_key as _,
        out_len as _,
        digest as _,
        prk as _,
        prk_len as _,
        info as _,
        info_len as _,
    ) as _
}

// EVP_AEAD_CTX
#[inline]
#[allow(non_snake_case)]
unsafe fn EVP_AEAD_CTX_init(
    ctx: *mut EVP_AEAD_CTX, aead: *const EVP_AEAD, key: *const u8,
    key_len: usize, tag_len: usize, engine: *mut c_void,
) -> c_int {
    sys::EVP_AEAD_CTX_init(
        ctx as _,
        aead as _,
        key as _,
        key_len as _,
        tag_len as _,
        engine as _,
    ) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn EVP_AEAD_CTX_open(
    ctx: *const EVP_AEAD_CTX, out: *mut u8, out_len: *mut usize,
    max_out_len: usize, nonce: *const u8, nonce_len: usize, inp: *const u8,
    in_len: usize, ad: *const u8, ad_len: usize,
) -> c_int {
    sys::EVP_AEAD_CTX_open(
        ctx as _,
        out as _,
        out_len as _,
        max_out_len as _,
        nonce as _,
        nonce_len as _,
        inp as _,
        in_len as _,
        ad as _,
        ad_len as _,
    ) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn EVP_AEAD_CTX_seal_scatter(
    ctx: *const EVP_AEAD_CTX, out: *mut u8, out_tag: *mut u8,
    out_tag_len: *mut usize, max_out_tag_len: usize, nonce: *const u8,
    nonce_len: usize, inp: *const u8, in_len: usize, extra_in: *const u8,
    extra_in_len: usize, ad: *const u8, ad_len: usize,
) -> c_int {
    sys::EVP_AEAD_CTX_seal_scatter(
        ctx as _,
        out as _,
        out_tag as _,
        out_tag_len as _,
        max_out_tag_len as _,
        nonce as _,
        nonce_len as _,
        inp as _,
        in_len as _,
        extra_in as _,
        extra_in_len as _,
        ad as _,
        ad_len as _,
    ) as _
}

// AES
#[inline]
#[allow(non_snake_case)]
unsafe fn AES_set_encrypt_key(
    key: *const u8, bits: c_uint, aeskey: *mut AES_KEY,
) -> c_int {
    sys::AES_set_encrypt_key(key as _, bits as _, aeskey as _) as _
}

#[inline]
#[allow(non_snake_case)]
unsafe fn AES_ecb_encrypt(
    inp: *const u8, out: *mut u8, key: *const AES_KEY, enc: c_int,
) {
    sys::AES_ecb_encrypt(inp as _, out as _, key as _, enc as _);
}

// ChaCha20
#[inline]
#[allow(non_snake_case)]
unsafe fn CRYPTO_chacha_20(
    out: *mut u8, inp: *const u8, in_len: usize, key: *const u8,
    nonce: *const u8, counter: u32,
) {
    sys::CRYPTO_chacha_20(
        out as _,
        inp as _,
        in_len as _,
        key as _,
        nonce as _,
        counter as _,
    );
}
