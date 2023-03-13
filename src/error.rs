use std::io;
use std::string;

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
    #[error("unexpected PADS")]
    UnexpectedPads,
    #[error("session ID is zero")]
    ZeroSession,
    #[error("unexpected PPP session traffic")]
    UnexpectedPpp,
    #[error("invalid PPP sub-protocol {0}")]
    InvalidProtocol(u16),
    #[error("invalid LCP code {0}")]
    InvalidLcpCode(u8),
    #[error("configuration acknowledged, but options differ from request")]
    AckedWrongOptions,
    #[error("configuration not acknowledged")]
    ConfigNak,
    #[error("configuration rejected")]
    ConfigReject,
    #[error("unexpected acknowledgement of link termination")]
    UnexpectedTermAck,
    #[error("invalid CHAP code {0}")]
    InvalidChapCode(u8),
    #[error("invalid IPCP code {0}")]
    InvalidIpcpCode(u8),
    #[error("io error")]
    Io(#[from] io::Error),
    #[error("failed to convert string from UTF-8")]
    Utf8(#[from] string::FromUtf8Error),
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
