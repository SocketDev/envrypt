//! Output layer (logger, colors, color_depth, truncate). Internal diagnostics
//! plumbing: the public entry routes `Logger` output to an optional
//! `on_diagnostic` callback. Output is line-based only; a library must not animate
//! stderr.
pub mod color_depth;
pub mod colors;
pub mod logger;
pub mod truncate;
