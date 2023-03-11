use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("usage: missing interface argument")]
    MissingInterface,
    #[error("client has already been started")]
    AlreadyActive,
    #[error("no active PPPoE session")]
    NoSession,
    #[error("bytes transmitted is not equal to request size")]
    PartialRequest,
    #[error("invalid packet code {0}")]
    InvalidCode(u8),
    #[error("unexpected PADS from MAC {0}")]
    UnexpectedPads(String),
    #[error("session terminated by peer")]
    Terminated,
    #[error("session ID is zero")]
    ZeroSession,
    #[error("invalid PPP sub-protocol {0}")]
    InvalidProtocol(u16),
    #[error("invalid LCP code {0}")]
    InvalidLcpCode(u8),
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
