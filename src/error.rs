use std::io;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("an error")]
    GeneralError(String),
    #[error("an error handling server responses")]
    ServerError(String),
    #[error(transparent)]
    IOError(#[from] io::Error),
    #[error(transparent)]
    NativeTlsError(#[from] native_tls::Error,),
    #[error(transparent)]
    OpenSslError(#[from] openssl::error::Error),
    #[error(transparent)]
    OpenSslErrorStack(#[from] openssl::error::ErrorStack)
}
