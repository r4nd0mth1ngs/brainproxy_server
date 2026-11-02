//! Object storage for the work directory (PLAN.md phase 4): S3 (and MinIO), Azure Blob, or a local
//! folder, behind the `object-store` cargo feature.
//!
//! For hosts whose disk doesn't outlive the container (Fargate, Azure Container Apps), the server
//! copies what it needs to start again into the store, and on a start with no `control.db` it
//! restores from there first. One server per store: two would overwrite each other.
//!
//! ```text
//! <prefix>/control.db                         a consistent copy (VACUUM INTO)
//! <prefix>/targets/<id>/project.bpdb          the newest project snapshot (`project save`)
//! <prefix>/targets/<id>/runs/<run>/<file>     the run's folder
//! <prefix>/manifest.json                      every object's SHA-256, signed
//! ```
//!
//! A restore trusts only what the manifest lists, with the hash it lists, and the manifest only
//! when its HMAC verifies under a key derived from the admin token, which the store never holds:
//! a bucket writer can't plant a target, a token or a file. It can still withhold uploads or put
//! back an older signed state (and with it a revoked token), so the bucket stays the server's own.
//!
//! Uploads happen in the background, a few seconds after a change (a run's end, an admin
//! operation), and once more on shutdown. A failed upload is retried a minute later.
//!
//! `<prefix>/lease.json` keeps a second server off the store: a server takes it before restoring,
//! renews it every minute and gives it back on shutdown. A server that finds another's lease
//! waits for it to end (a crashed server's runs out after three minutes), and one that loses
//! its lease exits. It guards against an overlapping deployment, not against two servers started
//! at the same instant.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;

use tokio::sync::{mpsc, oneshot};

use super::{Server, target};

/// Changes are gathered for this long before an upload.
const DEBOUNCE: Duration = Duration::from_secs(5);
/// After a failed upload, the next try.
const RETRY: Duration = Duration::from_secs(60);
/// How long a lease lasts without renewal, and how often it is renewed.
const LEASE_MS: i64 = 3 * 60 * 1000;
const RENEW: Duration = Duration::from_secs(60);
/// How long a starting server waits for another's lease.
pub const LEASE_WAIT: Duration = Duration::from_secs(5 * 60);

/// Something to copy to the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// A run's folder.
    Run { target: String, run: String },
    /// A target's project: `snapshot` when a fresh one exists, else `project save` makes one.
    Project { target: String, snapshot: Option<PathBuf> },
    /// A removed target: its objects go.
    Removed { target: String },
    /// control.db; every batch ends with it.
    Control,
}

enum Msg {
    Item(Item),
    Flush(oneshot::Sender<bool>),
}

/// The handle the server keeps: queues items for the sync task.
pub struct Sync {
    tx: mpsc::UnboundedSender<Msg>,
}

impl Sync {
    pub fn push(&self, item: Item) {
        let _ = self.tx.send(Msg::Item(item));
    }

    /// Uploads whatever is pending now, waiting at most `limit`; whether everything made it.
    pub async fn flush(&self, limit: Duration) -> bool {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Msg::Flush(tx)).is_ok() && matches!(tokio::time::timeout(limit, rx).await, Ok(Ok(true)))
    }
}

/// Starts the sync task for `server`, whose `store` must be set.
pub fn start(server: Arc<Server>) -> Sync {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(worker(server, rx));
    Sync { tx }
}

/// Renews the lease every minute from now on. A server whose lease another took exits: what it
/// changed from then on would never reach the store, and a restart would silently undo it.
pub fn keep_lease(store: Arc<Store>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(RENEW).await;
            if store.renew().await {
                eprintln!("brainproxy-server: {}: another server took the store; stopping", store.url);
                std::process::exit(1);
            }
        }
    });
}

async fn worker(server: Arc<Server>, mut rx: mpsc::UnboundedReceiver<Msg>) {
    let Some(store) = server.store.as_ref() else { return };
    let mut pending: Vec<Item> = Vec::new();
    let add = |pending: &mut Vec<Item>, item: Item| {
        if !pending.contains(&item) {
            pending.push(item);
        }
    };
    loop {
        // Wait for a change, or for the retry of a failed batch.
        let mut flushes = Vec::new();
        let first = if pending.is_empty() {
            rx.recv().await
        } else {
            match tokio::time::timeout(RETRY, rx.recv()).await {
                Ok(m) => m,
                Err(_) => Some(Msg::Item(Item::Control)),
            }
        };
        match first {
            None => return,
            Some(Msg::Item(i)) => add(&mut pending, i),
            Some(Msg::Flush(f)) => flushes.push(f),
        }
        let deadline = tokio::time::Instant::now() + DEBOUNCE;
        while flushes.is_empty() {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(Msg::Item(i))) => add(&mut pending, i),
                Ok(Some(Msg::Flush(f))) => flushes.push(f),
                Ok(None) | Err(_) => break,
            }
        }
        // Whatever arrived meanwhile goes into this batch too.
        while let Ok(m) = rx.try_recv() {
            match m {
                Msg::Item(i) => add(&mut pending, i),
                Msg::Flush(f) => flushes.push(f),
            }
        }
        if !pending.is_empty() {
            add(&mut pending, Item::Control);
            // Removals first, control.db last: a restored control.db never names a run or target
            // whose files didn't make it.
            pending.sort_by_key(|i| match i {
                Item::Removed { .. } => 0,
                Item::Run { .. } => 1,
                Item::Project { .. } => 2,
                Item::Control => 3,
            });
            let mut failed = Vec::new();
            if store.held.load(Ordering::SeqCst) {
                for item in std::mem::take(&mut pending) {
                    if let Err(e) = server.upload(store, &item).await {
                        eprintln!("brainproxy-server: store {}: {item:?}: {e}", store.url);
                        failed.push(item);
                    }
                }
                // The manifest last: it signs what is in the store now.
                if let Err(e) = store.put_manifest().await {
                    eprintln!("brainproxy-server: store {}: manifest: {e}", store.url);
                    failed.push(Item::Control);
                }
            } else {
                failed = std::mem::take(&mut pending);
            }
            pending = failed;
        }
        for f in flushes {
            let _ = f.send(pending.is_empty());
        }
    }
}

impl Server {
    /// Queues an item for the store, when there is one.
    pub fn sync(&self, item: Item) {
        if let Some(s) = self.sync.get() {
            s.push(item);
        }
    }

    async fn upload(&self, store: &Store, item: &Item) -> Result<(), String> {
        match item {
            Item::Run { target, run } => {
                store.put_dir(&self.run_dir(target, run), &format!("targets/{target}/runs/{run}")).await
            }
            Item::Project { target, snapshot } => {
                let key = format!("targets/{target}/project.bpdb");
                if let Some(s) = snapshot.as_ref().filter(|s| s.exists()) {
                    return store.put_file(s, &key).await;
                }
                if !self.target_dir(target).join("project.bpdb").exists() {
                    return Ok(()); // removed meanwhile, or an upload target still waiting
                }
                let tmp = self.cfg.work.join(".sync").join(format!("{target}.bpdb"));
                let _ = std::fs::create_dir_all(tmp.parent().unwrap_or(&self.cfg.work));
                let _ = std::fs::remove_file(&tmp);
                self.save_project(target, &tmp).await?;
                let r = store.put_file(&tmp, &key).await;
                let _ = std::fs::remove_file(&tmp);
                r
            }
            Item::Removed { target } => store.delete_prefix(&format!("targets/{target}")).await,
            Item::Control => {
                let tmp = self.cfg.work.join(".sync").join("control.db");
                let _ = std::fs::create_dir_all(tmp.parent().unwrap_or(&self.cfg.work));
                let _ = std::fs::remove_file(&tmp);
                self.db().backup_to(&tmp).map_err(|e| format!("copying control.db: {e}"))?;
                let r = store.put_file(&tmp, "control.db").await;
                let _ = std::fs::remove_file(&tmp);
                r
            }
        }
    }
}

/// Restores `work` from the store when it has no control.db: the targets' projects and runs first,
/// control.db last, so an interrupted restore runs again on the next start. Only objects the
/// signed manifest lists come back, each checked against its hash. Returns how many targets came
/// back, or `None` when there is nothing to restore.
pub async fn restore(store: &Store, work: &Path) -> Result<Option<usize>, String> {
    let control = work.join("control.db");
    if control.exists() {
        return Ok(None);
    }
    let Some(bytes) = store.get_bytes(MANIFEST).await? else {
        if store.has("control.db").await? {
            return Err(format!("{}: there is a control.db but no {MANIFEST}; not restoring from it", store.url));
        }
        return Ok(None);
    };
    let objects = store.verify(&bytes)?;
    let staging = work.join(".restore");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    let copy = staging.join("control.db");
    let hash = objects.get("control.db").ok_or_else(|| format!("{}: the manifest lists no control.db", store.url))?;
    store.get_file("control.db", &copy, hash).await?;
    let ids: Vec<String> = super::db::Db::open(&copy)
        .and_then(|db| db.targets().map_err(|e| e.to_string()))
        .map_err(|e| format!("the stored control.db: {e}"))?
        .into_iter()
        .map(|t| t.config.id)
        .collect();
    if let Some(bad) = ids.iter().find(|id| !target::valid_id(id)) {
        return Err(format!("the stored control.db has a target id {bad:?} the server never accepts"));
    }
    let mut kept = BTreeMap::from([("control.db".to_string(), hash.clone())]);
    for (key, hash) in &objects {
        let Some(rest) = key.strip_prefix("targets/") else { continue };
        let Some((id, rel)) = rest.split_once('/') else { continue };
        if !ids.iter().any(|i| i == id) {
            continue;
        }
        let parts: Vec<&str> = rel.split('/').collect();
        if !parts.iter().all(|p| valid_part(p)) {
            return Err(format!("the manifest lists {key:?}, which isn't a path the server writes"));
        }
        let path = parts.iter().fold(work.join("targets").join(id), |p, part| p.join(part));
        store.get_file(key, &path, hash).await?;
        kept.insert(key.clone(), hash.clone());
    }
    // The copy was opened above, which may have left WAL files beside it; it is consistent alone.
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(staging.join(format!("control.db{suffix}")));
    }
    *store.manifest.lock().unwrap_or_else(|e| e.into_inner()) = kept;
    store.save_manifest()?;
    std::fs::rename(&copy, &control).map_err(|e| format!("{}: {e}", control.display()))?;
    let _ = std::fs::remove_dir_all(&staging);
    Ok(Some(ids.len()))
}

const MANIFEST: &str = "manifest.json";

/// A file or folder name under a target's folder, as the server and the CLI write them.
fn valid_part(p: &str) -> bool {
    (1..=128).contains(&p.len())
        && !p.starts_with('.')
        && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// An object store and the prefix the server's objects live under.
pub struct Store {
    /// As given, for messages.
    pub url: String,
    /// This server's name in the lease, and whether it holds the lease.
    holder: String,
    held: AtomicBool,
    /// Signs the manifest; derived from the admin token.
    mac_key: ring::hmac::Key,
    /// What this server put in the store (key → SHA-256), and its copy in the work directory.
    manifest: Mutex<BTreeMap<String, String>>,
    manifest_file: PathBuf,
    /// No local manifest at start: everything is uploaded once.
    pub fresh: bool,
    #[cfg(feature = "object-store")]
    os: Arc<dyn object_store::ObjectStore>,
    #[cfg(feature = "object-store")]
    prefix: object_store::path::Path,
}

impl Store {
    #[cfg(feature = "object-store")]
    fn new_holder() -> String {
        super::auth::base32(&super::auth::random_bytes::<10>())
    }

    /// The manifest key: the admin token's hash, hashed again for this use only.
    #[cfg(feature = "object-store")]
    fn mac_key(admin_hash: &[u8; 32]) -> ring::hmac::Key {
        use sha2::{Digest, Sha256};
        let k = Sha256::new().chain_update(b"brainproxy-server store manifest\0").chain_update(admin_hash).finalize();
        ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &k)
    }

    /// The local manifest (`WORK/.sync/manifest.json`), if there is one.
    #[cfg(feature = "object-store")]
    fn load_manifest(path: &Path) -> Option<BTreeMap<String, String>> {
        serde_json::from_slice(&std::fs::read(path).ok()?).ok()
    }

    fn save_manifest(&self) -> Result<(), String> {
        let m = self.manifest.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(dir) = self.manifest_file.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        super::write_atomic(&self.manifest_file, &serde_json::to_vec(&m).unwrap_or_default())
            .map_err(|e| format!("{}: {e}", self.manifest_file.display()))
    }

    /// Signs and uploads the manifest, and keeps the local copy.
    async fn put_manifest(&self) -> Result<(), String> {
        let objects = self.manifest.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let signed = serde_json::to_vec(&objects).unwrap_or_default();
        let mac = ring::hmac::sign(&self.mac_key, &signed);
        let hex: String = mac.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        let body = json!({"version": 1, "objects": objects, "mac": hex});
        self.put_bytes(MANIFEST, body.to_string().into_bytes()).await?;
        self.save_manifest()
    }

    /// The objects a stored manifest lists, if its signature verifies.
    fn verify(&self, bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
        let refuse = |why: &str| {
            format!(
                "{}: {MANIFEST} {why}; not restoring (was it signed with another admin token, or changed?)",
                self.url
            )
        };
        let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| refuse("isn't JSON"))?;
        let objects: BTreeMap<String, String> =
            serde_json::from_value(v["objects"].clone()).map_err(|_| refuse("has no object list"))?;
        let mac = v["mac"].as_str().unwrap_or_default();
        let mac: Vec<u8> =
            (0..mac.len() / 2).filter_map(|i| u8::from_str_radix(mac.get(2 * i..2 * i + 2)?, 16).ok()).collect();
        ring::hmac::verify(&self.mac_key, &serde_json::to_vec(&objects).unwrap_or_default(), &mac)
            .map_err(|_| refuse("doesn't verify"))?;
        Ok(objects)
    }

    /// Uploads a file and records its hash in the manifest.
    async fn put_file(&self, local: &Path, key: &str) -> Result<(), String> {
        let hash = sha256_file(local)?;
        self.put_raw(local, key).await?;
        self.manifest.lock().unwrap_or_else(|e| e.into_inner()).insert(key.to_string(), hash);
        Ok(())
    }

    /// Uploads every file under `local` to `key/<relative path>`.
    async fn put_dir(&self, local: &Path, key: &str) -> Result<(), String> {
        let mut stack = vec![local.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{}: {e}", dir.display())),
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(kind) = entry.file_type() else { continue };
                if kind.is_dir() {
                    stack.push(path);
                } else if kind.is_file()
                    && let Ok(rel) = path.strip_prefix(local)
                {
                    let rel: Vec<String> = rel.iter().map(|p| p.to_string_lossy().into_owned()).collect();
                    self.put_file(&path, &format!("{key}/{}", rel.join("/"))).await?;
                }
            }
        }
        Ok(())
    }

    /// Deletes every object under `key/` and its manifest entries.
    async fn delete_prefix(&self, key: &str) -> Result<(), String> {
        self.delete_raw(key).await?;
        let dir = format!("{key}/");
        self.manifest.lock().unwrap_or_else(|e| e.into_inner()).retain(|k, _| !k.starts_with(&dir));
        Ok(())
    }

    /// The lease's holder and end, if there is one.
    async fn lease(&self) -> Result<Option<(String, i64)>, String> {
        let Some(bytes) = self.get_bytes("lease.json").await? else { return Ok(None) };
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        Ok(Some((v["holder"].as_str().unwrap_or_default().to_string(), v["until"].as_i64().unwrap_or(0))))
    }

    async fn write_lease(&self) -> Result<(), String> {
        let host = std::env::var("HOSTNAME").unwrap_or_default();
        let until = crate::time::now_millis() + LEASE_MS;
        let body = json!({"holder": self.holder, "host": host, "until": until});
        self.put_bytes("lease.json", body.to_string().into_bytes()).await
    }

    /// Takes the lease, waiting up to `wait` for another server's to end.
    pub async fn acquire(&self, wait: Duration) -> Result<(), String> {
        let start = std::time::Instant::now();
        let mut said = false;
        loop {
            match self.lease().await? {
                Some((holder, until)) if holder != self.holder && until > crate::time::now_millis() => {
                    if start.elapsed() >= wait {
                        return Err(format!(
                            "{}: another server holds the store until {} (one server per store; stop the other first)",
                            self.url,
                            crate::time::format_millis(until)
                        ));
                    }
                    if !said {
                        eprintln!(
                            "brainproxy-server: {}: another server holds the store until {}; waiting",
                            self.url,
                            crate::time::format_millis(until)
                        );
                        said = true;
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                _ => {
                    self.write_lease().await?;
                    self.held.store(true, Ordering::SeqCst);
                    return Ok(());
                }
            }
        }
    }

    /// Extends the lease. Returns true when another server has taken it meanwhile.
    async fn renew(&self) -> bool {
        if !self.held.load(Ordering::SeqCst) {
            return false;
        }
        let result = match self.lease().await {
            Ok(Some((holder, _))) if holder != self.holder => {
                self.held.store(false, Ordering::SeqCst);
                return true;
            }
            Ok(_) => self.write_lease().await,
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            eprintln!("brainproxy-server: {}: renewing the lease: {e}", self.url);
        }
        false
    }

    /// Gives the lease back, on shutdown after the last upload.
    pub async fn release(&self) {
        if self.held.swap(false, Ordering::SeqCst)
            && let Ok(Some((holder, _))) = self.lease().await
            && holder == self.holder
            && let Err(e) = self.delete_key("lease.json").await
        {
            eprintln!("brainproxy-server: {}: releasing the lease: {e}", self.url);
        }
    }
}

#[cfg(not(feature = "object-store"))]
impl Store {
    pub fn open(_url: &str, _admin_hash: &[u8; 32], _work: &Path) -> Result<Store, String> {
        Err("--store needs a server built with the object-store feature (cargo build --features object-store)".into())
    }
    async fn put_raw(&self, _local: &Path, _key: &str) -> Result<(), String> {
        unreachable!("no Store without the object-store feature")
    }
    async fn get_file(&self, _key: &str, _local: &Path, _hash: &str) -> Result<(), String> {
        unreachable!("no Store without the object-store feature")
    }
    async fn delete_raw(&self, _key: &str) -> Result<(), String> {
        unreachable!("no Store without the object-store feature")
    }
    pub async fn has(&self, _key: &str) -> Result<bool, String> {
        unreachable!("no Store without the object-store feature")
    }
    async fn get_bytes(&self, _key: &str) -> Result<Option<Vec<u8>>, String> {
        unreachable!("no Store without the object-store feature")
    }
    async fn put_bytes(&self, _key: &str, _bytes: Vec<u8>) -> Result<(), String> {
        unreachable!("no Store without the object-store feature")
    }
    async fn delete_key(&self, _key: &str) -> Result<(), String> {
        unreachable!("no Store without the object-store feature")
    }
}

#[cfg(feature = "object-store")]
impl Store {
    /// Opens `s3://bucket/prefix`, `az://container/prefix` (or `azure://`) or `file:///path`.
    /// Credentials and endpoints come from the usual variables (`AWS_*`, `AZURE_*`), as the
    /// providers' own tools read them; MinIO is `s3://` with `AWS_ENDPOINT` (and `AWS_ALLOW_HTTP`).
    /// The manifest is signed with a key derived from `admin_hash`, and its local copy is kept in
    /// `work`.
    pub fn open(url: &str, admin_hash: &[u8; 32], work: &Path) -> Result<Store, String> {
        let parsed = url::Url::parse(url).map_err(|e| format!("--store {url}: {e}"))?;
        if !matches!(parsed.scheme(), "s3" | "s3a" | "az" | "azure" | "abfs" | "abfss" | "file") {
            return Err(format!("--store {url}: use s3://, az:// or file://"));
        }
        if parsed.scheme() == "file" {
            let dir = Path::new(parsed.path());
            std::fs::create_dir_all(dir).map_err(|e| format!("--store {url}: {e}"))?;
        }
        // IDENTITY_ENDPOINT: managed identity on Azure Container Apps and App Service.
        let options = std::env::vars()
            .filter(|(k, _)| k.starts_with("AWS_") || k.starts_with("AZURE_") || k == "IDENTITY_ENDPOINT");
        let (os, prefix) = object_store::parse_url_opts(&parsed, options).map_err(|e| format!("--store {url}: {e}"))?;
        let manifest_file = work.join(".sync").join(MANIFEST);
        let local = Store::load_manifest(&manifest_file);
        Ok(Store {
            url: url.to_string(),
            holder: Store::new_holder(),
            held: AtomicBool::new(false),
            mac_key: Store::mac_key(admin_hash),
            fresh: local.is_none(),
            manifest: Mutex::new(local.unwrap_or_default()),
            manifest_file,
            os: Arc::from(os),
            prefix,
        })
    }

    fn key(&self, key: &str) -> object_store::path::Path {
        key.split('/').fold(self.prefix.clone(), |p, part| p.join(part))
    }

    /// Streams a file to `key`, in parts when it's large.
    async fn put_raw(&self, local: &Path, key: &str) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::File::open(local).await.map_err(|e| format!("{}: {e}", local.display()))?;
        let mut w = object_store::buffered::BufWriter::new(self.os.clone(), self.key(key));
        if let Err(e) = tokio::io::copy(&mut file, &mut w).await {
            let _ = w.abort().await;
            return Err(format!("uploading {key}: {e}"));
        }
        w.shutdown().await.map_err(|e| format!("uploading {key}: {e}"))
    }

    /// Downloads `key` to `local` through a temporary file, which only becomes `local` when its
    /// SHA-256 is `hash`.
    async fn get_file(&self, key: &str, local: &Path, hash: &str) -> Result<(), String> {
        use futures_util::StreamExt;
        use object_store::ObjectStoreExt;
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;
        let got = self.os.get(&self.key(key)).await.map_err(|e| format!("downloading {key}: {e}"))?;
        if let Some(parent) = local.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let tmp = local.with_extension("part");
        let mut file = tokio::fs::File::create(&tmp).await.map_err(|e| format!("{}: {e}", tmp.display()))?;
        let mut h = Sha256::new();
        let mut stream = got.into_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("downloading {key}: {e}"))?;
            h.update(&chunk);
            file.write_all(&chunk).await.map_err(|e| format!("{}: {e}", tmp.display()))?;
        }
        file.sync_all().await.map_err(|e| format!("{}: {e}", tmp.display()))?;
        let got: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if got != hash {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("{}: {key} doesn't match its hash in the manifest; not restoring", self.url));
        }
        std::fs::rename(&tmp, local).map_err(|e| format!("{}: {e}", local.display()))
    }

    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        use object_store::ObjectStoreExt;
        match self.os.get(&self.key(key)).await {
            Ok(g) => Ok(Some(g.bytes().await.map_err(|e| format!("{}: {key}: {e}", self.url))?.to_vec())),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(format!("{}: {key}: {e}", self.url)),
        }
    }

    async fn put_bytes(&self, key: &str, bytes: Vec<u8>) -> Result<(), String> {
        use object_store::ObjectStoreExt;
        self.os.put(&self.key(key), bytes.into()).await.map(drop).map_err(|e| format!("{}: {key}: {e}", self.url))
    }

    async fn delete_key(&self, key: &str) -> Result<(), String> {
        use object_store::ObjectStoreExt;
        self.os.delete(&self.key(key)).await.map_err(|e| format!("{}: {key}: {e}", self.url))
    }

    pub async fn has(&self, key: &str) -> Result<bool, String> {
        use object_store::ObjectStoreExt;
        match self.os.head(&self.key(key)).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(format!("{}: {key}: {e}", self.url)),
        }
    }

    /// Deletes every object under `key/`.
    async fn delete_raw(&self, key: &str) -> Result<(), String> {
        use futures_util::TryStreamExt;
        use object_store::ObjectStoreExt;
        let prefix = self.key(key);
        let objects: Vec<_> =
            self.os.list(Some(&prefix)).try_collect().await.map_err(|e| format!("listing {key}: {e}"))?;
        for o in objects {
            self.os.delete(&o.location).await.map_err(|e| format!("deleting {}: {e}", o.location))?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "object-store"))]
mod tests {
    use super::*;

    const ADMIN: [u8; 32] = [7; 32];

    fn open(bucket: &Path, work: &Path) -> Store {
        Store::open(&format!("file://{}/prefix", bucket.display()), &ADMIN, work).unwrap()
    }

    /// A store with control.db (holding one target, `shop`) and a run of it, as a server leaves it.
    async fn filled(bucket: &Path, src: &Path) -> Store {
        let store = open(bucket, src);
        let db = super::super::db::Db::open(&src.join("control.db")).unwrap();
        let mut t: target::TargetConfig = serde_json::from_value(json!({
            "id": "shop", "base_url": "https://shop.example.test/", "scope": ["shop.example.test"],
            "preset": "quick", "max_minutes": 10,
        }))
        .unwrap();
        t.validate(false).unwrap();
        db.insert_target(&t, true, 0).unwrap();
        let copy = src.join("copy.db");
        db.backup_to(&copy).unwrap();
        store.put_file(&copy, "control.db").await.unwrap();
        let run = src.join("run");
        std::fs::create_dir_all(run.join("sub")).unwrap();
        std::fs::write(run.join("run.json"), b"{}").unwrap();
        std::fs::write(run.join("sub/report.html"), vec![b'x'; 3 << 20]).unwrap();
        store.put_dir(&run, "targets/shop/runs/r1").await.unwrap();
        store.put_manifest().await.unwrap();
        store
    }

    #[tokio::test]
    async fn a_restore_brings_back_only_what_the_manifest_signs() {
        let (bucket, src) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        filled(bucket.path(), src.path()).await;
        let objects = bucket.path().join("prefix");
        assert!(objects.join("targets/shop/runs/r1/sub/report.html").exists());

        // An object nobody signed is left behind.
        std::fs::write(objects.join("targets/shop/planted.txt"), b"x").unwrap();
        let work = tempfile::tempdir().unwrap();
        let store = open(bucket.path(), work.path());
        assert!(store.fresh);
        assert_eq!(restore(&store, work.path()).await.unwrap(), Some(1));
        let dir = work.path().join("targets/shop");
        assert_eq!(std::fs::read(dir.join("runs/r1/run.json")).unwrap(), b"{}");
        assert_eq!(std::fs::metadata(dir.join("runs/r1/sub/report.html")).unwrap().len(), 3 << 20);
        assert!(!dir.join("planted.txt").exists());
        assert!(work.path().join("control.db").exists());
        assert!(!open(bucket.path(), work.path()).fresh, "the restore keeps a local manifest");
        assert_eq!(restore(&store, work.path()).await.unwrap(), None, "control.db exists");

        // A changed object, or a manifest signed with another key, stops the restore.
        std::fs::write(objects.join("targets/shop/runs/r1/run.json"), b"{\"changed\": 1}").unwrap();
        let work = tempfile::tempdir().unwrap();
        let e = restore(&open(bucket.path(), work.path()), work.path()).await.unwrap_err();
        assert!(e.contains("doesn't match its hash"), "{e}");
        assert!(!work.path().join("control.db").exists());
        let other = Store::open(&format!("file://{}/prefix", bucket.path().display()), &[8; 32], work.path()).unwrap();
        let e = restore(&other, work.path()).await.unwrap_err();
        assert!(e.contains("doesn't verify"), "{e}");
    }

    #[tokio::test]
    async fn removed_targets_leave_the_store_and_the_manifest() {
        let (bucket, src) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let store = filled(bucket.path(), src.path()).await;
        store.delete_prefix("targets/shop").await.unwrap();
        store.put_manifest().await.unwrap();
        assert!(!bucket.path().join("prefix/targets/shop").join("runs/r1/run.json").exists());
        let m = store.manifest.lock().unwrap().clone();
        assert_eq!(m.keys().collect::<Vec<_>>(), ["control.db"]);
    }

    #[test]
    fn restored_paths() {
        assert!(valid_part("report.html") && valid_part("r-20261102T160028Z-vjcwkd"));
        for bad in ["..", ".hidden", "", "a b", "x\\y", "%2E%2E"] {
            assert!(!valid_part(bad), "{bad}");
        }
    }

    #[tokio::test]
    async fn one_server_per_store() {
        let (bucket, work) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (open(bucket.path(), work.path()), open(bucket.path(), work.path()));
        a.acquire(Duration::ZERO).await.unwrap();
        let e = b.acquire(Duration::ZERO).await.unwrap_err();
        assert!(e.contains("another server holds the store"), "{e}");
        a.release().await;
        b.acquire(Duration::ZERO).await.unwrap();
        // A taken-over lease is noticed at the old holder's next renewal.
        a.held.store(true, Ordering::SeqCst);
        assert!(a.renew().await);
        assert!(!b.renew().await);
    }

    #[test]
    fn store_urls() {
        let work = tempfile::tempdir().unwrap();
        assert!(Store::open("http://example.com/x", &ADMIN, work.path()).is_err());
        assert!(Store::open("ftp://x/y", &ADMIN, work.path()).is_err());
    }
}
