use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("usage: missing interface argument")]
    MissingInterface,
    #[error("bytes transmitted is not equal to request size")]
    PartialRequest,
    #[error("expected PADO, got {0}")]
    ExpectedPado(u8),
    #[error("io error")]
    Io(#[from] io::Error),
    #[error("pppoe error: {0:?}")]
    Pppoe(pppoe::error::Error),
    #[error("pppoe parse error: {0:?}")]
    PppoeParse(pppoe::error::ParseError),
}

impl From<pppoe::error::Error> for Error {
    fn from(err: pppoe::error::Error) -> Self {
        Self::Pppoe(err)
    }
}

impl From<pppoe::error::ParseError> for Error {
    fn from(err: pppoe::error::ParseError) -> Self {
        Self::PppoeParse(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
