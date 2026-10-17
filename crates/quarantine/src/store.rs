//! Where quarantined message bytes live. Keys are spool message ids.
use async_trait::async_trait;
use currawong_core::{config::BlobStoreConfig, residency::ResidencyGuard};
use object_store::{
    aws::AmazonS3Builder,
    client::{
        ClientOptions, HttpClient, HttpConnector, HttpError, HttpErrorKind, HttpRequest,
        HttpResponse, HttpService,
    },
    path::Path as ObjectPath,
    ObjectStore, ObjectStoreExt,
};
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use url::Url;

#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn put(&self, key: &str, bytes: &[u8]) -> io::Result<()>;
    async fn get(&self, key: &str) -> io::Result<Vec<u8>>;
    /// Deleting a missing blob is not an error.
    async fn delete(&self, key: &str) -> io::Result<()>;
}

/// One file per message, mode 0600, written to a temporary name, synced and
/// renamed so a crash never leaves a partial blob.
#[derive(Debug, Clone)]
pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { root })
    }

    pub fn path(&self, key: &str) -> io::Result<PathBuf> {
        check_key(key)?;
        Ok(self.root.join(format!("{key}.eml")))
    }
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> io::Result<()> {
        let path = self.path(key)?;
        let tmp = path.with_extension("eml.tmp");
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp).await?;
        tokio::io::AsyncWriteExt::write_all(&mut file, bytes).await?;
        file.sync_all().await?;
        tokio::fs::rename(&tmp, &path).await?;
        sync_dir(&self.root).await
    }

    async fn get(&self, key: &str) -> io::Result<Vec<u8>> {
        tokio::fs::read(self.path(key)?).await
    }

    async fn delete(&self, key: &str) -> io::Result<()> {
        match tokio::fs::remove_file(self.path(key)?).await {
            Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
            _ => Ok(()),
        }
    }
}

async fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    tokio::fs::File::open(dir).await?.sync_all().await?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// An S3-compatible bucket. The endpoint must pass the residency guard
/// before a client exists, and every request goes through [`GuardedHttp`].
#[derive(Debug, Clone)]
pub struct S3BlobStore {
    store: Arc<dyn ObjectStore>,
}

impl S3BlobStore {
    pub fn new(guard: Arc<ResidencyGuard>, cfg: &BlobStoreConfig) -> Result<Self, String> {
        let endpoint =
            Url::parse(&cfg.endpoint).map_err(|err| format!("{}: {err}", cfg.endpoint))?;
        guard
            .check_request(&endpoint)
            .map_err(|err| err.to_string())?;
        if endpoint.scheme() != "https" {
            return Err(format!(
                "quarantine blob endpoint {endpoint} must use https"
            ));
        }
        // Path-style requests keep every request on the checked endpoint host.
        let store = AmazonS3Builder::from_env()
            .with_endpoint(endpoint.as_str().trim_end_matches('/'))
            .with_bucket_name(&cfg.bucket)
            .with_region(&cfg.region)
            .with_virtual_hosted_style_request(false)
            .with_http_connector(GuardedHttp { guard })
            .build()
            .map_err(|err| err.to_string())?;
        Ok(Self::from_store(Arc::new(store)))
    }

    /// Any `object_store` backend; tests use the in-memory one.
    pub fn from_store(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn put(&self, key: &str, bytes: &[u8]) -> io::Result<()> {
        check_key(key)?;
        self.store
            .put(&ObjectPath::from(key), bytes.to_vec().into())
            .await
            .map(|_| ())
            .map_err(io::Error::other)
    }

    async fn get(&self, key: &str) -> io::Result<Vec<u8>> {
        check_key(key)?;
        match self.store.get(&ObjectPath::from(key)).await {
            Ok(found) => Ok(found.bytes().await.map_err(io::Error::other)?.to_vec()),
            Err(object_store::Error::NotFound { .. }) => {
                Err(io::Error::new(io::ErrorKind::NotFound, "blob not found"))
            }
            Err(err) => Err(io::Error::other(err)),
        }
    }

    async fn delete(&self, key: &str) -> io::Result<()> {
        check_key(key)?;
        match self.store.delete(&ObjectPath::from(key)).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(err) => Err(io::Error::other(err)),
        }
    }
}

/// object_store HTTP that, like `GuardedClient`, checks, resolves and pins
/// every request through the residency guard and never follows a redirect:
/// an S3 307 to another region fails instead of carrying the message there.
struct GuardedHttp {
    guard: Arc<ResidencyGuard>,
}

impl std::fmt::Debug for GuardedHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuardedHttp")
    }
}

impl HttpConnector for GuardedHttp {
    fn connect(&self, _: &ClientOptions) -> object_store::Result<HttpClient> {
        Ok(HttpClient::new(GuardedService {
            guard: Arc::clone(&self.guard),
            pinned: Mutex::new(None),
        }))
    }
}

struct GuardedService {
    guard: Arc<ResidencyGuard>,
    /// One client per pinned address, rebuilt when the address changes.
    pinned: Mutex<Option<(SocketAddr, reqwest::Client)>>,
}

impl std::fmt::Debug for GuardedService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GuardedService")
    }
}

#[async_trait]
impl HttpService for GuardedService {
    async fn call(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let url = Url::parse(&request.uri().to_string())
            .map_err(|err| HttpError::new(HttpErrorKind::Request, err))?;
        let peer = self
            .guard
            .resolve(&url)
            .await
            .map_err(|err| HttpError::new(HttpErrorKind::Request, err))?;
        let client = self.client(&url, peer)?;
        client.call(request).await
    }
}

impl GuardedService {
    fn client(&self, url: &Url, peer: SocketAddr) -> Result<reqwest::Client, HttpError> {
        let mut pinned = self.pinned.lock().unwrap_or_else(|err| err.into_inner());
        if let Some((_, client)) = pinned.as_ref().filter(|(addr, _)| *addr == peer) {
            return Ok(client.clone());
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .resolve(url.host_str().unwrap_or_default(), peer)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|err| HttpError::new(HttpErrorKind::Connect, err))?;
        *pinned = Some((peer, client.clone()));
        Ok(client)
    }
}

/// The configured blob store: `fs` under `dir/blobs`, or `s3`.
pub fn open_blob_store(
    cfg: &BlobStoreConfig,
    guard: &Arc<ResidencyGuard>,
    dir: &Path,
) -> Result<Arc<dyn BlobStore>, String> {
    match cfg.kind.as_str() {
        "s3" => Ok(Arc::new(S3BlobStore::new(Arc::clone(guard), cfg)?)),
        _ => Ok(Arc::new(
            FsBlobStore::open(dir.join("blobs")).map_err(|err| err.to_string())?,
        )),
    }
}

/// Spool ids: 26 upper-case letters and digits, so a key is never a path.
pub(crate) fn check_key(key: &str) -> io::Result<()> {
    if currawong_spool::is_safe_id(key) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsafe quarantine id",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use currawong_core::config::ResidencyConfig;

    const KEY: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    #[tokio::test]
    async fn fs_blobs_are_private_and_deletable() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = FsBlobStore::open(dir.path().join("blobs")).unwrap();
        blobs.put(KEY, b"raw").await.unwrap();
        assert_eq!(blobs.get(KEY).await.unwrap(), b"raw");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(blobs.path(KEY).unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        blobs.delete(KEY).await.unwrap();
        blobs.delete(KEY).await.unwrap();
        assert!(blobs.get(KEY).await.is_err());
        assert!(blobs.put("../../etc/passwd", b"x").await.is_err());
    }

    #[tokio::test]
    async fn s3_store_round_trips_through_object_store() {
        let blobs = S3BlobStore::from_store(Arc::new(object_store::memory::InMemory::new()));
        blobs.put(KEY, b"raw").await.unwrap();
        assert_eq!(blobs.get(KEY).await.unwrap(), b"raw");
        blobs.delete(KEY).await.unwrap();
        let err = blobs.get(KEY).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn s3_store_refuses_a_bucket_outside_australia() {
        let guard = Arc::new(ResidencyGuard::from_config(&ResidencyConfig::default()).unwrap());
        let mut cfg = BlobStoreConfig {
            kind: "s3".into(),
            endpoint: "https://s3.us-east-1.amazonaws.com".into(),
            bucket: "held".into(),
            region: "us-east-1".into(),
        };
        assert!(S3BlobStore::new(Arc::clone(&guard), &cfg).is_err());
        cfg.endpoint = "https://s3.ap-southeast-2.amazonaws.com".into();
        cfg.region = "ap-southeast-2".into();
        S3BlobStore::new(guard, &cfg).unwrap();
    }
}
