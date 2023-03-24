use std::io;
use std::string;
use std::sync::mpsc;

use rsdsl_ip_config::IpConfig;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("client already started")]
    AlreadyActive,
    #[error("no active PPPoE session")]
    NoSession,
    #[error("bytes sent not equal to pkt size")]
    PartialTransmission,
    #[error("too many retransmissions: {0}")]
    TooManyRetransmissions(String),
    #[error("invalid pkt code {0}")]
    InvalidCode(u8),
    #[error("unexpected pads")]
    UnexpectedPads,
    #[error("session id can't be zero")]
    ZeroSession,
    #[error("unexpected ppp session traffic")]
    UnexpectedPpp,
    #[error("invalid ppp sub-protocol {0}")]
    InvalidProtocol(u16),
    #[error("invalid lcp code {0}")]
    InvalidLcpCode(u8),
    #[error("configure-ack, but opts don't match req")]
    AckedWrongOptions,
    #[error("configure-nak")]
    ConfigNak,
    #[error("configure-reject")]
    ConfigReject,
    #[error("unexpected lcp terminate-ack")]
    UnexpectedTermAck,
    #[error("invalid chap code {0}")]
    InvalidChapCode(u8),
    #[error("invalid ipcp code {0}")]
    InvalidIpcpCode(u8),
    #[error("no ip addr in ipcp configure-nak")]
    MissingIpAddr,
    #[error("no dns1 in ipcp configure-nak")]
    MissingPrimaryDns,
    #[error("no dns2 in ipcp configure-nak")]
    MissingSecondaryDns,
    #[error("ipcp closed")]
    Disconnected,
    #[error("io error")]
    Io(#[from] io::Error),
    #[error("can't create string from UTF-8")]
    Utf8(#[from] string::FromUtf8Error),
    #[error("mpsc send error")]
    MpscSendBytes(#[from] mpsc::SendError<Vec<u8>>),
    #[error("mpsc send error")]
    MpscSendBytesOpt(#[from] mpsc::SendError<Option<Vec<u8>>>),
    #[error("mpsc send error")]
    MpscSendIpConfig(#[from] mpsc::SendError<IpConfig>),
    #[error("mpsc recv error")]
    MpscRecv(#[from] mpsc::RecvError),
    #[error("pppoe error: {0:?}")]
    Pppoe(pppoe::error::Error),
    #[error("pppoe parse error: {0:?}")]
    PppoeParse(pppoe::error::ParseError),
    #[error("rsdsl_netlinkd error")]
    RsdslNetlinkd(#[from] rsdsl_netlinkd::error::Error),
    #[error("serde_json error")]
    SerdeJson(#[from] serde_json::Error),
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
