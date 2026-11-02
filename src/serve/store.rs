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
//! ```
//!
//! Uploads happen in the background, a few seconds after a change (a run's end, an admin
//! operation), and once more on shutdown. A failed upload is retried a minute later.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use super::Server;

/// Changes are gathered for this long before an upload.
const DEBOUNCE: Duration = Duration::from_secs(5);
/// After a failed upload, the next try.
const RETRY: Duration = Duration::from_secs(60);

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
    Flush(oneshot::Sender<()>),
}

/// The handle the server keeps: queues items for the sync task.
pub struct Sync {
    tx: mpsc::UnboundedSender<Msg>,
}

impl Sync {
    pub fn push(&self, item: Item) {
        let _ = self.tx.send(Msg::Item(item));
    }

    /// Uploads whatever is pending now, waiting at most `limit`.
    pub async fn flush(&self, limit: Duration) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Msg::Flush(tx)).is_ok() {
            let _ = tokio::time::timeout(limit, rx).await;
        }
    }
}

/// Starts the sync task for `server`, whose `store` must be set.
pub fn start(server: Arc<Server>) -> Sync {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(worker(server, rx));
    Sync { tx }
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
            for item in std::mem::take(&mut pending) {
                if let Err(e) = server.upload(store, &item).await {
                    eprintln!("brainproxy-server: store {}: {item:?}: {e}", store.url);
                    failed.push(item);
                }
            }
            pending = failed;
        }
        for f in flushes {
            let _ = f.send(());
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
/// control.db last, so an interrupted restore runs again on the next start. Returns how many
/// targets came back, or `None` when the store holds nothing yet.
pub async fn restore(store: &Store, work: &Path) -> Result<Option<usize>, String> {
    let control = work.join("control.db");
    if control.exists() {
        return Ok(None);
    }
    let staging = work.join(".restore");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| format!("{}: {e}", staging.display()))?;
    let copy = staging.join("control.db");
    if !store.get_file("control.db", &copy).await? {
        let _ = std::fs::remove_dir_all(&staging);
        return Ok(None);
    }
    let ids: Vec<String> = super::db::Db::open(&copy)
        .and_then(|db| db.targets().map_err(|e| e.to_string()))
        .map_err(|e| format!("the stored control.db: {e}"))?
        .into_iter()
        .map(|t| t.config.id)
        .collect();
    for id in &ids {
        let dir = work.join("targets").join(id);
        store.get_dir(&format!("targets/{id}"), &dir).await?;
    }
    // The copy was opened above, which may have left WAL files beside it; it is consistent alone.
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(staging.join(format!("control.db{suffix}")));
    }
    std::fs::rename(&copy, &control).map_err(|e| format!("{}: {e}", control.display()))?;
    let _ = std::fs::remove_dir_all(&staging);
    Ok(Some(ids.len()))
}

/// An object store and the prefix the server's objects live under.
pub struct Store {
    /// As given, for messages.
    pub url: String,
    #[cfg(feature = "object-store")]
    os: Arc<dyn object_store::ObjectStore>,
    #[cfg(feature = "object-store")]
    prefix: object_store::path::Path,
}

#[cfg(not(feature = "object-store"))]
impl Store {
    pub fn open(_url: &str) -> Result<Store, String> {
        Err("--store needs a server built with the object-store feature (cargo build --features object-store)".into())
    }
    async fn put_file(&self, _local: &Path, _key: &str) -> Result<(), String> {
        unreachable!("no Store without the object-store feature")
    }
    async fn put_dir(&self, _local: &Path, _key: &str) -> Result<(), String> {
        unreachable!("no Store without the object-store feature")
    }
    async fn get_file(&self, _key: &str, _local: &Path) -> Result<bool, String> {
        unreachable!("no Store without the object-store feature")
    }
    async fn get_dir(&self, _key: &str, _local: &Path) -> Result<(), String> {
        unreachable!("no Store without the object-store feature")
    }
    async fn delete_prefix(&self, _key: &str) -> Result<(), String> {
        unreachable!("no Store without the object-store feature")
    }
    pub async fn has(&self, _key: &str) -> Result<bool, String> {
        unreachable!("no Store without the object-store feature")
    }
}

#[cfg(feature = "object-store")]
impl Store {
    /// Opens `s3://bucket/prefix`, `az://container/prefix` (or `azure://`) or `file:///path`.
    /// Credentials and endpoints come from the usual variables (`AWS_*`, `AZURE_*`), as the
    /// providers' own tools read them; MinIO is `s3://` with `AWS_ENDPOINT` (and `AWS_ALLOW_HTTP`).
    pub fn open(url: &str) -> Result<Store, String> {
        let parsed = url::Url::parse(url).map_err(|e| format!("--store {url}: {e}"))?;
        if !matches!(parsed.scheme(), "s3" | "s3a" | "az" | "azure" | "abfs" | "abfss" | "file") {
            return Err(format!("--store {url}: use s3://, az:// or file://"));
        }
        if parsed.scheme() == "file" {
            let dir = Path::new(parsed.path());
            std::fs::create_dir_all(dir).map_err(|e| format!("--store {url}: {e}"))?;
        }
        let options = std::env::vars().filter(|(k, _)| k.starts_with("AWS_") || k.starts_with("AZURE_"));
        let (os, prefix) = object_store::parse_url_opts(&parsed, options).map_err(|e| format!("--store {url}: {e}"))?;
        Ok(Store { url: url.to_string(), os: Arc::from(os), prefix })
    }

    fn key(&self, key: &str) -> object_store::path::Path {
        key.split('/').fold(self.prefix.clone(), |p, part| p.join(part))
    }

    /// Streams a file to `key`, in parts when it's large.
    async fn put_file(&self, local: &Path, key: &str) -> Result<(), String> {
        use tokio::io::AsyncWriteExt;
        let mut file = tokio::fs::File::open(local).await.map_err(|e| format!("{}: {e}", local.display()))?;
        let mut w = object_store::buffered::BufWriter::new(self.os.clone(), self.key(key));
        if let Err(e) = tokio::io::copy(&mut file, &mut w).await {
            let _ = w.abort().await;
            return Err(format!("uploading {key}: {e}"));
        }
        w.shutdown().await.map_err(|e| format!("uploading {key}: {e}"))
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

    /// Downloads `key` to `local` (through a temporary file); `false` when there's no such object.
    async fn get_file(&self, key: &str, local: &Path) -> Result<bool, String> {
        use futures_util::StreamExt;
        use object_store::ObjectStoreExt;
        use tokio::io::AsyncWriteExt;
        let got = match self.os.get(&self.key(key)).await {
            Ok(g) => g,
            Err(object_store::Error::NotFound { .. }) => return Ok(false),
            Err(e) => return Err(format!("downloading {key}: {e}")),
        };
        if let Some(parent) = local.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let tmp = local.with_extension("part");
        let mut file = tokio::fs::File::create(&tmp).await.map_err(|e| format!("{}: {e}", tmp.display()))?;
        let mut stream = got.into_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("downloading {key}: {e}"))?;
            file.write_all(&chunk).await.map_err(|e| format!("{}: {e}", tmp.display()))?;
        }
        file.sync_all().await.map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, local).map_err(|e| format!("{}: {e}", local.display()))?;
        Ok(true)
    }

    /// Downloads every object under `key/` into `local`, keeping the relative paths.
    async fn get_dir(&self, key: &str, local: &Path) -> Result<(), String> {
        use futures_util::TryStreamExt;
        let prefix = self.key(key);
        let objects: Vec<_> =
            self.os.list(Some(&prefix)).try_collect().await.map_err(|e| format!("listing {key}: {e}"))?;
        for o in objects {
            let Some(rel) = o.location.prefix_match(&prefix) else { continue };
            let rel: Vec<String> = rel.map(|p| p.as_ref().to_string()).collect();
            // Path parts are validated by object_store (no "..", no separators), but stay careful.
            if rel.is_empty() || rel.iter().any(|p| p.is_empty() || p == "." || p == "..") {
                continue;
            }
            let path = rel.iter().fold(local.to_path_buf(), |p, part| p.join(part));
            self.get_file(&format!("{key}/{}", rel.join("/")), &path).await?;
        }
        Ok(())
    }

    pub async fn has(&self, key: &str) -> Result<bool, String> {
        use object_store::ObjectStoreExt;
        match self.os.head(&self.key(key)).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(format!("{}: {key}: {e}", self.url)),
        }
    }

    async fn delete_prefix(&self, key: &str) -> Result<(), String> {
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

    #[tokio::test]
    async fn files_and_folders_round_trip() {
        let bucket = tempfile::tempdir().unwrap();
        let local = tempfile::tempdir().unwrap();
        let store = Store::open(&format!("file://{}/prefix", bucket.path().display())).unwrap();
        let run = local.path().join("run");
        std::fs::create_dir_all(run.join("sub")).unwrap();
        std::fs::write(run.join("run.json"), b"{}").unwrap();
        std::fs::write(run.join("sub/report.html"), vec![b'x'; 3 << 20]).unwrap();
        store.put_dir(&run, "targets/shop/runs/r1").await.unwrap();
        assert!(bucket.path().join("prefix/targets/shop/runs/r1/sub/report.html").exists());

        let back = local.path().join("back");
        store.get_dir("targets/shop", &back).await.unwrap();
        assert_eq!(std::fs::read(back.join("runs/r1/run.json")).unwrap(), b"{}");
        assert_eq!(std::fs::metadata(back.join("runs/r1/sub/report.html")).unwrap().len(), 3 << 20);
        assert!(!store.get_file("nothing", &local.path().join("n")).await.unwrap());

        store.delete_prefix("targets/shop").await.unwrap();
        let mut left = Vec::new();
        store.get_dir("targets/shop", &local.path().join("gone")).await.unwrap();
        if let Ok(d) = std::fs::read_dir(local.path().join("gone")) {
            left.extend(d.flatten().map(|e| e.path()));
        }
        assert!(left.is_empty(), "{left:?}");
    }

    #[test]
    fn store_urls() {
        assert!(Store::open("http://example.com/x").is_err());
        assert!(Store::open("ftp://x/y").is_err());
    }
}
