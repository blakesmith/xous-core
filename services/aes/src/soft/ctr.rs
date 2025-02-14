//! AES in counter mode (a.k.a. AES-CTR)

// TODO(tarcieri): support generic CTR API

use super::{Aes128Soft, Aes192, Aes256Soft};

/// AES-128 in CTR mode
#[cfg_attr(docsrs, doc(cfg(feature = "ctr")))]
pub type Aes128Ctr = ::ctr::Ctr64BE<Aes128Soft>;

/// AES-192 in CTR mode
#[cfg_attr(docsrs, doc(cfg(feature = "ctr")))]
pub type Aes192Ctr = ::ctr::Ctr64BE<Aes192>;

/// AES-256 in CTR mode
#[cfg_attr(docsrs, doc(cfg(feature = "ctr")))]
pub type Aes256Ctr = ::ctr::Ctr64BE<Aes256Soft>;
