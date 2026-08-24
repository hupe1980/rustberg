//! Rustberg - A production-grade, cross-platform, single-binary Apache Iceberg REST Catalog.
//!
//! This crate provides the core functionality for the Rustberg Iceberg catalog service.

// Enforce no unsafe code across the entire crate
#![forbid(unsafe_code)]

mod app;
pub mod auth;
pub mod catalog;
pub mod config;
pub mod credentials;
pub mod error;
pub mod location;
pub mod management;
pub mod names;
pub mod observability;
pub mod predicate;
pub mod remote_ip;
pub mod server;
mod utils;

pub use app::*;
pub use server::start_server;
