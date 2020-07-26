//! third-wheel is a TLS man-in-the-middle proxy library. Using the crate allows
//! you to intercept, re-route, modify etc. in-flight HTTP requests and responses
//! between clients and servers. Client code just needs to provide a struct that `impl`'s
//! `MitmLayer`. Examples use cases can be found as binaries in the crate.


// Rustc lints
// <https://doc.rust-lang.org/rustc/lints/listing/allowed-by-default.html>
#![warn(
    anonymous_parameters,
    bare_trait_objects,
    elided_lifetimes_in_paths,
    missing_copy_implementations,
    rust_2018_idioms,
    single_use_lifetimes,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    //    unsafe_code, https://github.com/campbellC/third-wheel/issues/13
    unused_extern_crates,
    unused_import_braces
)]
// Clippy lints
// <https://rust-lang.github.io/rust-clippy/master/>
#![warn(
    clippy::all,
    clippy::cargo,
    clippy::dbg_macro,
    clippy::float_cmp_const,
    clippy::get_unwrap,
    clippy::mem_forget,
    clippy::nursery,
    clippy::option_unwrap_used,
    clippy::pedantic,
    clippy::result_unwrap_used,
    clippy::todo,
    clippy::wrong_pub_self_convention
)]
#![allow(clippy::multiple_crate_versions)] // TODO: find out why we depend on two versions of winapi

mod certificates;
mod proxy;

mod codecs;

pub use crate::certificates::create_signed_certificate_for_domain;
pub use crate::certificates::CertificateAuthority;
pub use proxy:: start_mitm;
pub use proxy::mitm::{RequestCapture, ResponseCapture, MitmLayer};

/// A poorly named result type. This will be replaced in https://github.com/campbellC/third-wheel/issues/17
pub type SafeResult = Result<(), Box<dyn std::error::Error>>;
