// Ensure the ICU4X C API is built and linked: SpiderMonkey's Segmenter code
// references icu4x_*_mv1 when MOZ_ICU4X is set (i.e. --with-intl-api).
pub use icu_capi;
