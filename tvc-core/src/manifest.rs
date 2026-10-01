//! Which weight files a reference run used: a signed list of file digests.
//!
//! # Why a file list, not the quantised commitment
//!
//! The question a reference record has to answer is "which files did you load",
//! and the honest unit for that is the file. A per-file SHA-256 list:
//!
//! - works for any size and any dtype (FP8, GGUF, anything), because it hashes
//!   bytes as they are rather than decoding tensors, and it streams, so a
//!   600 GB checkpoint needs a few megabytes of memory;
//! - matches what Hugging Face already publishes for every large file in a
//!   repository (its LFS `sha256`), so anyone can compare a manifest against the
//!   hub without downloading the weights;
//! - is the same shape as OpenSSF model signing's subject list (path, digest),
//!   so nothing here is a novel format a reader has to learn.
//!
//! The quantised Merkle commitment in [`crate::commitment`] is still the right
//! tool for opening a single weight; it is not needed to say which files ran.
//!
//! # What is and is not in a manifest
//!
//! Every regular file under the model directory, at any depth, except inside a
//! directory named `.git` or `.cache` (version-control metadata and the Hugging
//! Face download cache, neither of which is part of the model). File symlinks are
//! followed, because the Hugging Face cache lays a snapshot out as symlinks into
//! a blob store. Directory symlinks are refused rather than followed, so a link
//! cycle cannot make the walk loop.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use bitcoin_hashes::{sha256, HashEngine};
use serde_json::{json, Value};

use crate::error::{Result, TvcError};
use crate::hex;

/// Document kind for a weights manifest.
pub const KIND_WEIGHTS_MANIFEST: &str = "weights-manifest/v1";

/// Directory names skipped at any depth.
const SKIPPED_DIRS: [&str; 2] = [".git", ".cache"];

/// Read size for streaming hashes.
const CHUNK: usize = 1 << 20;

/// One file in a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestFile {
    /// Path relative to the model directory, `/`-separated.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 of the file's bytes.
    pub sha256: [u8; 32],
}

/// The files a model directory held, by digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeightsManifest {
    /// Model name as the reference refers to it, for example `Qwen/Qwen2.5-0.5B-Instruct`.
    pub model: String,
    /// Hugging Face repository the files came from, if any.
    pub hf_repo: Option<String>,
    /// Hugging Face commit the files came from, if any. A branch name like
    /// `main` is refused: it moves, and a manifest has to name one revision.
    pub hf_commit: Option<String>,
    /// Files in byte order of their paths, no duplicates.
    pub files: Vec<ManifestFile>,
}

/// One way a directory differs from a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestMismatch {
    /// Listed in the manifest, absent from the directory.
    Missing(String),
    /// Present in the directory, absent from the manifest.
    Extra(String),
    /// Present in both with different sizes.
    Size {
        /// Relative path.
        path: String,
        /// Size the manifest records.
        expected: u64,
        /// Size on disk.
        observed: u64,
    },
    /// Present in both, same size, different content.
    Digest {
        /// Relative path.
        path: String,
        /// Digest the manifest records, hex.
        expected: String,
        /// Digest of the file on disk, hex.
        observed: String,
    },
}

impl core::fmt::Display for ManifestMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing(path) => write!(f, "{path}: in the manifest, not on disk"),
            Self::Extra(path) => write!(f, "{path}: on disk, not in the manifest"),
            Self::Size { path, expected, observed } => {
                write!(f, "{path}: size {observed}, manifest says {expected}")
            }
            Self::Digest { path, expected, observed } => {
                write!(f, "{path}: sha256 {observed}, manifest says {expected}")
            }
        }
    }
}

impl WeightsManifest {
    /// Hashes every file under `dir`.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::Io`] for an unreadable file, and
    /// [`TvcError::InvalidDocument`] for a directory symlink, a non-UTF-8 path,
    /// an empty directory, or a `hf_commit` that is not a 40-character hex id.
    pub fn from_dir(
        dir: &Path,
        model: impl Into<String>,
        hf_repo: Option<String>,
        hf_commit: Option<String>,
    ) -> Result<Self> {
        let mut files = Vec::new();
        walk(dir, "", &mut files)?;
        files.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        let manifest = Self {
            model: model.into(),
            hf_repo,
            hf_commit,
            files,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Checks the manifest's own invariants.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidDocument`] naming the first problem.
    pub fn validate(&self) -> Result<()> {
        let bad = |reason: String| Err(TvcError::InvalidDocument(reason));
        if self.model.trim().is_empty() {
            return bad("manifest has no model name".to_owned());
        }
        if self.files.is_empty() {
            return bad("manifest lists no files".to_owned());
        }
        if let Some(commit) = &self.hf_commit {
            let is_commit = commit.len() == 40 && hex::decode(commit).is_ok();
            if !is_commit {
                return bad(format!(
                    "hf_commit {commit:?} is not a 40-character lowercase commit id; a branch name moves"
                ));
            }
        }
        if self.hf_commit.is_some() != self.hf_repo.is_some() {
            return bad("hf_repo and hf_commit must be given together".to_owned());
        }
        for pair in self.files.windows(2) {
            if pair[0].path.as_bytes() >= pair[1].path.as_bytes() {
                return bad(format!(
                    "files must be sorted with no duplicates; {:?} is followed by {:?}",
                    pair[0].path, pair[1].path
                ));
            }
        }
        for file in &self.files {
            validate_path(&file.path)?;
        }
        Ok(())
    }

    /// Renders the manifest as its published document.
    pub fn to_json(&self) -> Value {
        let files: Vec<Value> = self
            .files
            .iter()
            .map(|file| {
                json!({
                    "path": file.path,
                    "size": file.size,
                    "sha256": hex::encode(&file.sha256),
                })
            })
            .collect();
        let mut document = json!({
            "kind": KIND_WEIGHTS_MANIFEST,
            "model": self.model,
            "files": files,
        });
        if let (Some(repo), Some(commit)) = (&self.hf_repo, &self.hf_commit) {
            document["hf_repo"] = json!(repo);
            document["hf_commit"] = json!(commit);
        }
        document
    }

    /// Reads a published manifest document back, validating it.
    ///
    /// # Errors
    ///
    /// Returns [`TvcError::InvalidDocument`] for a wrong kind, a missing or
    /// mistyped field, or any failure of [`Self::validate`].
    pub fn from_json(document: &Value) -> Result<Self> {
        let bad = |reason: &str| TvcError::InvalidDocument(format!("weights manifest: {reason}"));
        if document.get("kind").and_then(Value::as_str) != Some(KIND_WEIGHTS_MANIFEST) {
            return Err(bad("kind is not weights-manifest/v1"));
        }
        let text = |key: &str| document.get(key).and_then(Value::as_str).map(str::to_owned);
        let mut files = Vec::new();
        for entry in document
            .get("files")
            .and_then(Value::as_array)
            .ok_or_else(|| bad("files is missing"))?
        {
            files.push(ManifestFile {
                path: entry
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("a file has no path"))?
                    .to_owned(),
                size: entry
                    .get("size")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| bad("a file has no size"))?,
                sha256: hex::decode_array::<32>(
                    entry
                        .get("sha256")
                        .and_then(Value::as_str)
                        .ok_or_else(|| bad("a file has no sha256"))?,
                )?,
            });
        }
        let manifest = Self {
            model: text("model").ok_or_else(|| bad("model is missing"))?,
            hf_repo: text("hf_repo"),
            hf_commit: text("hf_commit"),
            files,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Re-hashes `dir` and lists every way it differs from this manifest.
    ///
    /// An empty result means the directory holds exactly the listed files with
    /// exactly the listed contents, and nothing else.
    ///
    /// # Errors
    ///
    /// As [`Self::from_dir`], for problems reading the directory itself.
    pub fn verify_dir(&self, dir: &Path) -> Result<Vec<ManifestMismatch>> {
        let mut found = Vec::new();
        walk(dir, "", &mut found)?;
        found.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));

        let mut mismatches = Vec::new();
        let (mut expected, mut observed) = (self.files.iter().peekable(), found.iter().peekable());
        loop {
            match (expected.peek(), observed.peek()) {
                (None, None) => break,
                (Some(want), None) => {
                    mismatches.push(ManifestMismatch::Missing(want.path.clone()));
                    expected.next();
                }
                (None, Some(have)) => {
                    mismatches.push(ManifestMismatch::Extra(have.path.clone()));
                    observed.next();
                }
                (Some(want), Some(have)) => match want.path.as_bytes().cmp(have.path.as_bytes()) {
                    core::cmp::Ordering::Less => {
                        mismatches.push(ManifestMismatch::Missing(want.path.clone()));
                        expected.next();
                    }
                    core::cmp::Ordering::Greater => {
                        mismatches.push(ManifestMismatch::Extra(have.path.clone()));
                        observed.next();
                    }
                    core::cmp::Ordering::Equal => {
                        if want.size != have.size {
                            mismatches.push(ManifestMismatch::Size {
                                path: want.path.clone(),
                                expected: want.size,
                                observed: have.size,
                            });
                        } else if want.sha256 != have.sha256 {
                            mismatches.push(ManifestMismatch::Digest {
                                path: want.path.clone(),
                                expected: hex::encode(&want.sha256),
                                observed: hex::encode(&have.sha256),
                            });
                        }
                        expected.next();
                        observed.next();
                    }
                },
            }
        }
        Ok(mismatches)
    }
}

/// Refuses paths that could point outside the model directory or that have
/// two spellings.
fn validate_path(path: &str) -> Result<()> {
    let bad = |reason: &str| Err(TvcError::InvalidDocument(format!("file path {path:?}: {reason}")));
    if path.is_empty() || path.starts_with('/') || path.ends_with('/') {
        return bad("must be relative and must not start or end with '/'");
    }
    if path.contains('\\') || path.contains('\0') {
        return bad("must use '/' separators and contain no NUL");
    }
    if path.split('/').any(|part| part.is_empty() || part == "." || part == "..") {
        return bad("must not contain an empty, '.' or '..' component");
    }
    Ok(())
}

fn walk(dir: &Path, prefix: &str, out: &mut Vec<ManifestFile>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|error| TvcError::Io(format!("{}: {error}", dir.display())))?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| {
            TvcError::InvalidDocument(format!("{}: path is not UTF-8", entry.path().display()))
        })?;
        let relative = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let link = std::fs::symlink_metadata(entry.path())?;
        let target = std::fs::metadata(entry.path())
            .map_err(|error| TvcError::Io(format!("{}: {error}", entry.path().display())))?;

        if target.is_dir() {
            if link.file_type().is_symlink() {
                return Err(TvcError::InvalidDocument(format!(
                    "{relative}: directory symlinks are not followed"
                )));
            }
            if SKIPPED_DIRS.contains(&name) {
                continue;
            }
            walk(&entry.path(), &relative, out)?;
        } else if target.is_file() {
            let (size, digest) = hash_file(&entry.path())?;
            out.push(ManifestFile {
                path: relative,
                size,
                sha256: digest,
            });
        }
    }
    Ok(())
}

/// Streams a file through SHA-256.
///
/// # Errors
///
/// Returns [`TvcError::Io`] if the file cannot be read.
pub fn hash_file(path: &Path) -> Result<(u64, [u8; 32])> {
    let mut file =
        File::open(path).map_err(|error| TvcError::Io(format!("{}: {error}", path.display())))?;
    let mut engine = sha256::Hash::engine();
    let mut buffer = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        engine.input(&buffer[..read]);
        size += read as u64;
    }
    Ok((size, sha256::Hash::from_engine(engine).to_byte_array()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "tvc-manifest-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(path.join("sub")).unwrap();
            std::fs::write(path.join("config.json"), b"{\"layers\":2}").unwrap();
            std::fs::write(path.join("model.safetensors"), vec![7u8; 3_000_000]).unwrap();
            std::fs::write(path.join("sub/tokenizer.json"), b"{}").unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn manifest(dir: &Path) -> WeightsManifest {
        WeightsManifest::from_dir(dir, "acme/tiny", None, None).unwrap()
    }

    #[test]
    fn files_are_sorted_hashed_and_sized() {
        let scratch = Scratch::new("basic");
        let built = manifest(&scratch.0);
        let paths: Vec<&str> = built.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["config.json", "model.safetensors", "sub/tokenizer.json"]);
        assert_eq!(built.files[1].size, 3_000_000);
        // Streaming over 1 MiB chunks gives the one-shot digest.
        assert_eq!(
            built.files[1].sha256,
            crate::canonical::sha256_bytes(&vec![7u8; 3_000_000])
        );
        assert!(built.verify_dir(&scratch.0).unwrap().is_empty());
    }

    #[test]
    fn the_document_round_trips() {
        let scratch = Scratch::new("roundtrip");
        let built = WeightsManifest::from_dir(
            &scratch.0,
            "acme/tiny",
            Some("acme/tiny".to_owned()),
            Some("7ae557604adf67be50417f59c2c2f167def9a775".to_owned()),
        )
        .unwrap();
        assert_eq!(WeightsManifest::from_json(&built.to_json()).unwrap(), built);
    }

    #[test]
    fn every_kind_of_change_is_reported_by_name() {
        let scratch = Scratch::new("tamper");
        let built = manifest(&scratch.0);

        std::fs::write(scratch.0.join("config.json"), b"{\"layers\":3}").unwrap(); // same size
        std::fs::write(scratch.0.join("sub/tokenizer.json"), b"{ }").unwrap(); // new size
        std::fs::remove_file(scratch.0.join("model.safetensors")).unwrap();
        std::fs::write(scratch.0.join("extra.bin"), b"x").unwrap();

        let found = built.verify_dir(&scratch.0).unwrap();
        assert!(found.contains(&ManifestMismatch::Missing("model.safetensors".to_owned())));
        assert!(found.contains(&ManifestMismatch::Extra("extra.bin".to_owned())));
        assert!(found
            .iter()
            .any(|m| matches!(m, ManifestMismatch::Digest { path, .. } if path == "config.json")));
        assert!(found
            .iter()
            .any(|m| matches!(m, ManifestMismatch::Size { path, .. } if path == "sub/tokenizer.json")));
        assert_eq!(found.len(), 4);
    }

    #[test]
    fn a_renamed_file_is_a_missing_one_plus_an_extra_one() {
        let scratch = Scratch::new("rename");
        let built = manifest(&scratch.0);
        std::fs::rename(scratch.0.join("config.json"), scratch.0.join("config2.json")).unwrap();
        let found = built.verify_dir(&scratch.0).unwrap();
        assert_eq!(
            found,
            vec![
                ManifestMismatch::Missing("config.json".to_owned()),
                ManifestMismatch::Extra("config2.json".to_owned()),
            ]
        );
    }

    #[test]
    fn git_and_cache_directories_are_skipped() {
        let scratch = Scratch::new("skip");
        std::fs::create_dir_all(scratch.0.join(".git")).unwrap();
        std::fs::write(scratch.0.join(".git/HEAD"), b"ref").unwrap();
        std::fs::create_dir_all(scratch.0.join(".cache/huggingface")).unwrap();
        std::fs::write(scratch.0.join(".cache/huggingface/x.lock"), b"").unwrap();
        assert_eq!(manifest(&scratch.0).files.len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn file_symlinks_are_followed_and_directory_symlinks_refused() {
        let scratch = Scratch::new("links");
        let blob = scratch.0.join("blob");
        std::fs::write(&blob, b"weights").unwrap();
        std::os::unix::fs::symlink(&blob, scratch.0.join("linked.bin")).unwrap();
        let built = manifest(&scratch.0);
        let linked = built.files.iter().find(|f| f.path == "linked.bin").unwrap();
        assert_eq!(linked.sha256, crate::canonical::sha256_bytes(b"weights"));

        std::os::unix::fs::symlink(&scratch.0, scratch.0.join("sub/loop")).unwrap();
        assert!(matches!(
            WeightsManifest::from_dir(&scratch.0, "acme/tiny", None, None),
            Err(TvcError::InvalidDocument(_))
        ));
    }

    #[test]
    fn a_branch_name_is_not_a_revision() {
        let scratch = Scratch::new("branch");
        assert!(WeightsManifest::from_dir(
            &scratch.0,
            "acme/tiny",
            Some("acme/tiny".to_owned()),
            Some("main".to_owned()),
        )
        .is_err());
    }

    #[test]
    fn paths_that_escape_or_duplicate_are_refused() {
        let scratch = Scratch::new("paths");
        let mut built = manifest(&scratch.0);
        built.files[0].path = "../escape".to_owned();
        assert!(built.validate().is_err());

        let mut duplicated = manifest(&scratch.0);
        duplicated.files[1].path = duplicated.files[0].path.clone();
        assert!(duplicated.validate().is_err());
    }
}
