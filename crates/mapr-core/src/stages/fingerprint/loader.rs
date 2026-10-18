//! Range file loader: fetch, disk-cache, and offline handling.
//!
//! The loader is responsible for obtaining raw bytes for a `RangeSource`:
//!
//! 1. If a valid cache file exists (within `cache_ttl_secs`), return it.
//! 2. Otherwise, if `offline` is false, fetch from the provider URL and
//!    write the cache.
//! 3. If `offline` is true and no valid cache exists, return `None`
//!    (the stage will emit a `NoRangeData` gap).
//!
//! Cache layout: `<platform_cache_dir>/mapr/<source_name>.bin`.
//! The platform cache directory is resolved via the `directories` crate
//! (XDG on Linux, `~/Library/Caches` on macOS, `%LOCALAPPDATA%` on Windows).
//!
//! We store raw bytes from the HTTP response so re-parsing is always done
//! from the canonical source format. No credentials are ever stored.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use directories::ProjectDirs;

use crate::stages::fingerprint::range_db::RangeSource;

/// Default cache TTL: 24 hours.
pub const DEFAULT_CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Result of a load attempt.
pub enum LoadResult {
    /// Raw bytes obtained from cache or network.
    Data {
        bytes: Vec<u8>,
        /// True when served from the on-disk cache (not freshly fetched).
        from_cache: bool,
    },
    /// No cache and offline mode is active.
    NoData,
}

/// Configuration for a single load.
pub struct LoadConfig {
    /// When true, never make network requests.
    pub offline: bool,
    /// Maximum age of a cache file before it is considered stale.
    pub cache_ttl_secs: u64,
    /// Override the cache directory (useful in tests).
    pub cache_dir_override: Option<PathBuf>,
    /// HTTP timeout in seconds.
    pub http_timeout_secs: u64,
}

impl Default for LoadConfig {
    fn default() -> Self {
        Self {
            offline: false,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            cache_dir_override: None,
            http_timeout_secs: 30,
        }
    }
}

impl LoadConfig {
    fn cache_dir(&self) -> Option<PathBuf> {
        if let Some(ref ov) = self.cache_dir_override {
            return Some(ov.clone());
        }
        ProjectDirs::from("io", "mapr", "mapr").map(|p| p.cache_dir().to_path_buf())
    }

    fn cache_path(&self, source_name: &str) -> Option<PathBuf> {
        self.cache_dir()
            .map(|dir| dir.join(format!("{source_name}.bin")))
    }
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Load bytes for `source`, using the cache when valid and the network
/// otherwise.
///
/// This function is async because the network fetch uses `reqwest`. It does
/// not return errors; all failure modes produce `LoadResult::NoData` or
/// bubble up as the caller's gap.
pub async fn load(source: &dyn RangeSource, config: &LoadConfig) -> LoadResult {
    let cache_path = config.cache_path(source.name());

    // Try the cache first.
    if let Some(ref path) = cache_path {
        if let Some(bytes) = read_cache_if_valid(path, config.cache_ttl_secs) {
            return LoadResult::Data {
                bytes,
                from_cache: true,
            };
        }
    }

    // No valid cache.
    if config.offline {
        return LoadResult::NoData;
    }

    // Fetch from the network.
    match fetch(source.url(), config.http_timeout_secs).await {
        Ok(bytes) => {
            // Write to cache (best-effort; failure is non-fatal).
            if let Some(ref path) = cache_path {
                let _ = write_cache(path, &bytes);
            }
            LoadResult::Data {
                bytes,
                from_cache: false,
            }
        }
        Err(_) => LoadResult::NoData,
    }
}

// ---------------------------------------------------------------------------
// Cache helpers
// ---------------------------------------------------------------------------

/// Return cached bytes if the file exists and is younger than `ttl_secs`.
fn read_cache_if_valid(path: &Path, ttl_secs: u64) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    if age > Duration::from_secs(ttl_secs) {
        return None;
    }
    std::fs::read(path).ok()
}

/// Write bytes to the cache file, creating parent directories as needed.
fn write_cache(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)
}

// ---------------------------------------------------------------------------
// Network fetch
// ---------------------------------------------------------------------------

async fn fetch(url: &str, timeout_secs: u64) -> Result<Vec<u8>, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed for {url}: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {} fetching {url}", resp.status().as_u16()));
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("failed to read response body from {url}: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::stages::fingerprint::range_db::RangeEntry;

    /// A fake range source that always returns one entry.
    struct FakeSource;
    impl RangeSource for FakeSource {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn url(&self) -> &'static str {
            "https://example.invalid/fake"
        }
        fn parse(&self, _data: &[u8]) -> Result<Vec<RangeEntry>, String> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn offline_with_no_cache_returns_no_data() {
        let config = LoadConfig {
            offline: true,
            cache_dir_override: Some(std::env::temp_dir().join("mapr_test_nonexistent_xyz")),
            ..LoadConfig::default()
        };
        let result = load(&FakeSource, &config).await;
        assert!(matches!(result, LoadResult::NoData));
    }

    #[tokio::test]
    async fn cache_hit_returns_data_from_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("fake.bin");
        std::fs::write(&cache_path, b"cached-data").unwrap();

        let config = LoadConfig {
            offline: true,
            cache_ttl_secs: 3600,
            cache_dir_override: Some(dir.path().to_path_buf()),
            ..LoadConfig::default()
        };
        let result = load(&FakeSource, &config).await;
        match result {
            LoadResult::Data { bytes, from_cache } => {
                assert_eq!(bytes, b"cached-data");
                assert!(from_cache);
            }
            LoadResult::NoData => panic!("expected Data, got NoData"),
        }
    }

    #[tokio::test]
    async fn expired_cache_with_offline_returns_no_data() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("fake.bin");
        std::fs::write(&cache_path, b"stale").unwrap();

        // Set TTL to 0 so anything is expired.
        let config = LoadConfig {
            offline: true,
            cache_ttl_secs: 0,
            cache_dir_override: Some(dir.path().to_path_buf()),
            ..LoadConfig::default()
        };
        let result = load(&FakeSource, &config).await;
        assert!(matches!(result, LoadResult::NoData));
    }
}
