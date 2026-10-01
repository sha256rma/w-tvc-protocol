//! Comparing a weights manifest with what Hugging Face publishes.
//!
//! Hugging Face's API lists every file in a repository at a given commit. For
//! large files it also gives the SHA-256 of the content (the LFS object id), so
//! the weights themselves can be checked without downloading them. Small files
//! (configs, tokenizers) are stored as plain git blobs and the API only gives a
//! git SHA-1 for those, which is a hash of a different thing; those files are
//! downloaded and hashed instead. They are small.
//!
//! [`compare`] holds all the logic and takes the API response and a download
//! function as inputs, so it is tested offline against a recorded response.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use serde_json::Value;
use tvc_core::canonical::sha256_bytes;
use tvc_core::hex;
use tvc_core::manifest::WeightsManifest;

/// Largest non-LFS file this will download to hash.
const SMALL_FILE_LIMIT: u64 = 64 << 20;

/// How one manifest file compared with the repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    /// SHA-256 and size match the LFS record; nothing downloaded.
    LfsMatch,
    /// Downloaded and hashed; matches.
    DownloadedMatch,
    /// Differs from the repository; the reason says how.
    Mismatch(String),
    /// Not in the repository at this commit.
    NotInRepository,
}

/// The result for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCheck {
    /// Path relative to the repository root.
    pub path: String,
    /// Outcome.
    pub status: FileStatus,
}

/// The whole comparison.
#[derive(Debug, Clone)]
pub struct HfReport {
    /// One entry per manifest file.
    pub files: Vec<FileCheck>,
    /// Files in the repository that the manifest does not list. Not a failure:
    /// a reference may load a subset (it rarely needs the README), but it is
    /// reported so nobody mistakes "every listed file matched" for "every file
    /// in the repository was used".
    pub unlisted: Vec<String>,
}

impl HfReport {
    /// Whether every manifest file matched.
    pub fn all_match(&self) -> bool {
        self.files.iter().all(|f| {
            matches!(f.status, FileStatus::LfsMatch | FileStatus::DownloadedMatch)
        })
    }
}

/// Compares `manifest` against a Hugging Face API response.
///
/// `download` fetches a small file's bytes by path. It is only called for
/// files that have no LFS SHA-256.
///
/// # Errors
///
/// Returns a message if the manifest names no repository, or the response is
/// for a different commit than the manifest pins.
pub fn compare(
    manifest: &WeightsManifest,
    api: &Value,
    download: &dyn Fn(&str) -> Result<Vec<u8>, String>,
) -> Result<HfReport, String> {
    let commit = manifest
        .hf_commit
        .as_deref()
        .ok_or("the manifest names no hf_commit; there is nothing to compare against")?;
    let served = api.get("sha").and_then(Value::as_str).unwrap_or("");
    if served != commit {
        return Err(format!(
            "Hugging Face answered for commit {served:?}, the manifest pins {commit}"
        ));
    }

    let mut repository: BTreeMap<String, (u64, Option<String>)> = BTreeMap::new();
    for sibling in api
        .get("siblings")
        .and_then(Value::as_array)
        .ok_or("response has no file list")?
    {
        let Some(path) = sibling.get("rfilename").and_then(Value::as_str) else {
            continue;
        };
        let size = sibling.get("size").and_then(Value::as_u64).unwrap_or(0);
        let lfs = sibling
            .get("lfs")
            .and_then(|lfs| lfs.get("sha256"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        repository.insert(path.to_owned(), (size, lfs));
    }

    let mut files = Vec::new();
    for file in &manifest.files {
        let status = match repository.get(&file.path) {
            None => FileStatus::NotInRepository,
            Some((size, Some(lfs_sha))) => {
                if *size != file.size {
                    FileStatus::Mismatch(format!("size {size} on the hub, {} in the manifest", file.size))
                } else if *lfs_sha != hex::encode(&file.sha256) {
                    FileStatus::Mismatch(format!("sha256 {lfs_sha} on the hub"))
                } else {
                    FileStatus::LfsMatch
                }
            }
            Some((size, None)) => {
                if *size > SMALL_FILE_LIMIT {
                    FileStatus::Mismatch(format!(
                        "{size}-byte file has no LFS hash and is too large to download here"
                    ))
                } else {
                    match download(&file.path) {
                        Err(error) => FileStatus::Mismatch(format!("could not download: {error}")),
                        Ok(bytes) => {
                            if bytes.len() as u64 != file.size {
                                FileStatus::Mismatch(format!(
                                    "downloaded {} bytes, manifest says {}",
                                    bytes.len(),
                                    file.size
                                ))
                            } else if sha256_bytes(&bytes) != file.sha256 {
                                FileStatus::Mismatch(format!(
                                    "downloaded file hashes to {}",
                                    hex::encode(&sha256_bytes(&bytes))
                                ))
                            } else {
                                FileStatus::DownloadedMatch
                            }
                        }
                    }
                }
            }
        };
        files.push(FileCheck {
            path: file.path.clone(),
            status,
        });
    }

    let listed: std::collections::BTreeSet<&str> =
        manifest.files.iter().map(|f| f.path.as_str()).collect();
    let unlisted = repository
        .keys()
        .filter(|path| !listed.contains(path.as_str()))
        .cloned()
        .collect();
    Ok(HfReport { files, unlisted })
}

fn agent_get(url: &str) -> Result<ureq::Response, String> {
    let mut request = ureq::get(url).timeout(Duration::from_secs(60));
    if let Ok(token) = std::env::var("HF_TOKEN") {
        request = request.set("Authorization", &format!("Bearer {}", token.trim()));
    }
    request.call().map_err(|error| error.to_string())
}

/// Fetches the API response for the manifest's repository and commit, then
/// runs [`compare`], downloading small files as needed.
///
/// # Errors
///
/// Returns a message for a network failure or a manifest with no repository.
pub fn check(manifest: &WeightsManifest) -> Result<HfReport, String> {
    let (repo, commit) = match (&manifest.hf_repo, &manifest.hf_commit) {
        (Some(repo), Some(commit)) => (repo.as_str(), commit.as_str()),
        _ => return Err("the manifest names no hf_repo/hf_commit".to_owned()),
    };
    let body = agent_get(&format!(
        "https://huggingface.co/api/models/{repo}/revision/{commit}?blobs=true"
    ))?
    .into_string()
    .map_err(|error| error.to_string())?;
    let api: Value = serde_json::from_str(&body)
        .map_err(|error| format!("Hugging Face API response was not JSON: {error}"))?;

    let download = |path: &str| -> Result<Vec<u8>, String> {
        let response = agent_get(&format!("https://huggingface.co/{repo}/resolve/{commit}/{path}"))?;
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(SMALL_FILE_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        Ok(bytes)
    };
    compare(manifest, &api, &download)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tvc_core::manifest::ManifestFile;

    const COMMIT: &str = "7ae557604adf67be50417f59c2c2f167def9a775";

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../tests/fixtures/hf_qwen2.5-0.5b-instruct_7ae5576.json"
        ))
        .unwrap()
    }

    fn manifest(files: Vec<ManifestFile>) -> WeightsManifest {
        WeightsManifest {
            model: "Qwen/Qwen2.5-0.5B-Instruct".to_owned(),
            hf_repo: Some("Qwen/Qwen2.5-0.5B-Instruct".to_owned()),
            hf_commit: Some(COMMIT.to_owned()),
            files,
        }
    }

    fn weights_file() -> ManifestFile {
        ManifestFile {
            path: "model.safetensors".to_owned(),
            size: 988_097_824,
            sha256: hex::decode_array::<32>(
                "fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe",
            )
            .unwrap(),
        }
    }

    fn no_download(_: &str) -> Result<Vec<u8>, String> {
        Err("offline".to_owned())
    }

    #[test]
    fn the_weights_match_the_hub_without_a_download() {
        let report = compare(&manifest(vec![weights_file()]), &fixture(), &no_download).unwrap();
        assert_eq!(report.files[0].status, FileStatus::LfsMatch);
        assert!(report.all_match());
        assert!(report.unlisted.contains(&"config.json".to_owned()));
    }

    #[test]
    fn different_weights_are_caught_by_name() {
        let mut swapped = weights_file();
        swapped.sha256[0] ^= 1;
        let report = compare(&manifest(vec![swapped]), &fixture(), &no_download).unwrap();
        assert!(matches!(report.files[0].status, FileStatus::Mismatch(_)));
        assert!(!report.all_match());
    }

    #[test]
    fn a_small_file_is_downloaded_and_hashed() {
        let bytes = b"{\"stand-in\": true}".to_vec();
        let mut api = fixture();
        // Give config.json a size matching the stand-in bytes.
        for sibling in api["siblings"].as_array_mut().unwrap() {
            if sibling["rfilename"] == "config.json" {
                sibling["size"] = Value::from(bytes.len() as u64);
            }
        }
        let config = ManifestFile {
            path: "config.json".to_owned(),
            size: bytes.len() as u64,
            sha256: sha256_bytes(&bytes),
        };
        let served = bytes.clone();
        let fetch = move |path: &str| -> Result<Vec<u8>, String> {
            assert_eq!(path, "config.json");
            Ok(served.clone())
        };
        let report = compare(&manifest(vec![config.clone()]), &api, &fetch).unwrap();
        assert_eq!(report.files[0].status, FileStatus::DownloadedMatch);

        let tampered = move |_: &str| -> Result<Vec<u8>, String> { Ok(b"{\"stand-in\": fake}".to_vec()) };
        let report = compare(&manifest(vec![config]), &api, &tampered).unwrap();
        assert!(matches!(report.files[0].status, FileStatus::Mismatch(_)));
    }

    #[test]
    fn a_file_the_repository_never_had_is_reported() {
        let extra = ManifestFile {
            path: "adapter.safetensors".to_owned(),
            size: 1,
            sha256: [0; 32],
        };
        let report = compare(&manifest(vec![extra]), &fixture(), &no_download).unwrap();
        assert_eq!(report.files[0].status, FileStatus::NotInRepository);
    }

    #[test]
    fn a_response_for_another_commit_is_refused() {
        let mut api = fixture();
        api["sha"] = Value::from("0000000000000000000000000000000000000000");
        assert!(compare(&manifest(vec![weights_file()]), &api, &no_download).is_err());
    }
}
