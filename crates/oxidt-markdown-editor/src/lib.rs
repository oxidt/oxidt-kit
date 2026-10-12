//! A Markdown writing field shared by server-rendered and Dioxus apps.
//!
//! Enable `topcoat` or `dioxus` for a framework component. Both ship the same
//! browser module and keep a real textarea as the form value and fallback.
//! Saving, rendering published HTML, and uploading files belong to the app.

#[cfg(feature = "topcoat")]
pub mod topcoat;

#[cfg(feature = "dioxus")]
pub mod dioxus;
