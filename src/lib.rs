//! Rustberg - A production-grade, cross-platform, single-binary Apache Iceberg REST Catalog.
//!
//! This crate provides the core functionality for the Rustberg Iceberg catalog service.

// Enforce no unsafe code across the entire crate
#![deny(unsafe_code)]

mod app;
pub mod auth;
pub mod catalog;
pub mod config;
pub mod credentials;
pub mod crypto;
mod error;
pub mod observability;
pub mod openapi;
pub mod server;
#[cfg(feature = "slatedb-storage")]
pub mod storage;
mod utils;

pub use app::*;
pub use server::start_server;
