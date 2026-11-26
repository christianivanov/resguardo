//! Deterministic scanning pipeline and detectors (design document, Annex F; ADR 0008).
//!
//! Pure: no I/O and no clock. A [`Pipeline`] turns request texts into a
//! [`resguardo_core::ScanReport`]: findings by data class with their span in the original
//! text, and flags for content a limit kept from being fully inspected. Neither ever holds
//! the matched value.
#![forbid(unsafe_code)]

mod aggregate;
mod card;
mod decode;
mod email;
mod entropy;
mod es_id;
mod normalize;
mod phone;
mod pipeline;
mod scanner;
mod secrets;
mod windows;

pub use pipeline::{Pipeline, ScanError};

#[cfg(test)]
pub(crate) mod test_support {
    /// Deterministic pseudo-random numbers for property-style tests, without a dependency.
    pub(crate) struct Lcg(pub u64);

    impl Lcg {
        pub(crate) fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
    }
}
