//! Downloads a Habitat package from a [depot](../depot).
//!
//! # Examples
//!
//! ```bash
//! $ hab pkg download core/redis
//! ```
//!
//! Will download `core/redis` package from a custom depot:
//!
//! ```bash
//! $ hab pkg download core/redis/3.0.1 redis -u http://depot.co:9633
//! ```
//!
//! This would download the `3.0.1` version of redis.
//!
//! # Internals
//!
//! * Resolve the list of partial artifact identifiers to fully qualified idents
//! * Gather the TDEPS of the list (done concurrently with the above step)
//! * Download the artifact
//! * Verify it is un-altered
//! * Fetch the signing keys

use std::{collections::HashSet,
          path::{Path,
                 PathBuf},
          time::Duration};

use crate::{api_client::{self,
                         BoxedClient,
                         Client,
                         Error::APIError,
                         Package},
            hcore::{self,
                    crypto::{artifact,
                             keys::parse_name_with_rev,
                             SigKeyPair},
                    fs::{cache_artifact_path,
                         cache_key_path},
                    package::{PackageArchive,
                              PackageIdent,
                              PackageIdentTarget,
                              PackageTarget},
                    ChannelIdent}};

use reqwest::StatusCode;
use retry::{delay,
            retry};

use crate::{error::{Error,
                    Result},
            ui::{Status,
                 UIWriter}};

pub const RETRIES: usize = 5;
pub const RETRY_WAIT: Duration = Duration::from_millis(3000);

/// Download a Habitat package.
///
/// If an `PackageIdentTarget` is given, we retrieve the package from the specified Builder
/// `url`. Providing a fully-qualified identifer will result in that exact package being installed
/// (regardless of `channel`). Providing a partially-qualified identifier will result in the
/// installation of latest appropriate release from the given `channel`.
///
/// Any dependencies of will be retrieved from Builder (if they're not already cached locally).
///
/// At the end of this function, the specified package and all its dependencies will be downloaded
/// on the system.

/// Note: it's worth investigating whether
/// LocalPackageUsage makes sense here
/// Also, in the future we may want to accept an alternate builder to 'filter' what we pull down by
/// That would greatly optimize the 'sync' to on prem builder case, as we could point to that
/// and only fetch what we don't already have.
#[allow(clippy::too_many_arguments)]
pub fn start<U>(ui: &mut U,
                url: &str,
                channel: &ChannelIdent,
                product: &str,
                version: &str,
                idents: Vec<PackageIdent>,
                target: PackageTarget,
                download_path: Option<&PathBuf>,
                token: Option<&str>,
                verify: bool)
                -> Result<()>
    where U: UIWriter
{
    debug!("Starting download with url: {}, channel: {}, product: {}, version: {}, target: {}, \
            download_path: {:?}, token: {:?}, verify: {}",
           url, channel, product, version, target, download_path, token, verify);

    let key_download_path = &path_helper(download_path, "keys", &cache_key_path::<PathBuf>(None));
    debug!("install key_download_path: {:?}", key_download_path);

    let artifact_download_path = &path_helper(download_path,
                                              "artifacts",
                                              &cache_artifact_path::<PathBuf>(None));
    debug!("install artifact_download_path: {:?}",
           artifact_download_path);

    // We deliberately use None to specifiy the default path as this is used for cert paths, which
    // we don't want to override.
    let api_client = Client::new(url, product, version, None)?;
    let task = DownloadTask { idents,
                              target,
                              url,
                              api_client,
                              token,
                              channel,
                              artifact_download_path,
                              key_download_path,
                              verify };

    let downloaded_artifacts: Vec<PackageArchive> = task.execute(ui).unwrap();

    debug!("Expanded package count: {}", downloaded_artifacts.len());

    Ok(())
}

struct DownloadTask<'a> {
    idents: Vec<PackageIdent>,
    target: PackageTarget,
    url: &'a str,
    api_client: BoxedClient,
    token: Option<&'a str>,
    channel: &'a ChannelIdent,
    /// The path to the local artifact cache (e.g., /hab/cache/artifacts)
    artifact_download_path: &'a Path,
    key_download_path: &'a Path,
    verify: bool,
}

impl<'a> DownloadTask<'a> {
    fn execute<T>(&self, ui: &mut T) -> Result<Vec<PackageArchive>>
        where T: UIWriter
    {
        // This was written intentionally with an eye towards data parallelism
        // Any or all of these phases should naturally fit a fork-join model

        ui.begin(format!("Preparing to download necessary packages for {} idents",
                         self.idents.len()))?;
        ui.begin(format!("Using channel {} from {}", self.channel, self.url))?;
        ui.begin(format!("Storing in cache at {:?} ", self.artifact_download_path))?;

        // Phase 1: Expand to fully qualified deps and TDEPS
        let expanded_idents = self.expand_sources(ui)?;

        // Phase 2: Download artifacts
        let downloaded_artifacts = self.download_artifacts(ui, &expanded_idents)?;

        Ok(downloaded_artifacts)
    }

    // For each source, use the builder/depot to expand it to a fully qualifed form
    // The same call gives us the TDEPS, add those as
    fn expand_sources<T>(&self, ui: &mut T) -> Result<HashSet<PackageIdentTarget>>
        where T: UIWriter
    {
        let mut expanded_packages = Vec::<Package>::new();
        let mut expanded_idents = HashSet::<PackageIdentTarget>::new();

        // This loop should be easy to convert to a parallel map
        for ident in &self.idents {
            let latest = self.determine_latest_from_ident(ui,
                                                      &PackageIdentTarget { ident:  ident.clone(),
                                                                            target: self.target, });
            if let Ok(package) = latest {
                expanded_packages.push(package);
            }
        }

        // Collect all the expanded deps into one structure
        // Done separately because it's not as easy to parallelize
        for package in expanded_packages {
            expanded_idents.insert(PackageIdentTarget { ident:  package.ident,
                                                        target: self.target, });
            for ident in package.tdeps {
                expanded_idents.insert(PackageIdentTarget { ident,
                                                            target: self.target });
            }
        }

        ui.status(Status::Found,
                  format!("{} artifacts", expanded_idents.len()))?;

        Ok(expanded_idents)
    }

    fn download_artifacts<T>(&self,
                             ui: &mut T,
                             expanded_idents: &HashSet<PackageIdentTarget>)
                             -> Result<Vec<PackageArchive>>
        where T: UIWriter
    {
        let mut downloaded_artifacts = Vec::<PackageArchive>::new();

        ui.status(Status::Downloading,
                  format!("Downloading {} artifacts", expanded_idents.len()))?;

        for ident in expanded_idents {
            // TODO think through error handling here; failure to fetch, etc
            // Probably worth keeping statistics
            let archive: PackageArchive = self.get_cached_archive(ui, &ident)?;

            downloaded_artifacts.push(archive);
        }

        Ok(downloaded_artifacts)
    }

    fn determine_latest_from_ident<T>(&self,
                                      ui: &mut T,
                                      ident: &PackageIdentTarget)
                                      -> Result<Package>
        where T: UIWriter
    {
        // Unlike in the install command, we always hit the online
        // depot; our purpose is to sync with latest, and falling back
        // to a local package would defeat that. Find the latest
        // package in the proper channel from Builder API,
        ui.status(Status::Determining,
                  format!("latest version of {} in the '{}' channel",
                          &ident, self.channel))?;
        match self.fetch_latest_package_in_channel_for(ident, self.channel, self.token) {
            Ok(latest_package) => {
                ui.status(Status::Using,
                          format!("{} as latest matching {}", latest_package.ident, ident))?;
                Ok(latest_package)
            }
            Err(Error::APIClient(APIError(StatusCode::NOT_FOUND, _))) => {
                // In install we attempt to recommend a channel to look in. That's a bit of a
                // heavyweight process, and probably a bad idea in the context of
                // what's a normally a batch process. It might be ok to fall back to
                // the stable channel, but for now, error.
                ui.warn(format!("No packages matching ident {} for exist in the '{}' channel",
                                ident, self.channel))?;
                Err(Error::PackageNotFound(
                    format!("{} in channel {}", ident, self.channel).to_string(),
                ))
            }
            Err(e) => {
                debug!("error fetching ident {}: {:?}", ident, e);
                Err(e)
            }
        }
    }

    // This function and it's sibling get_cached_artifact in
    // install.rs deserve to be refactored to eke out commonality.
    /// This ensures the identified package is in the local cache,
    /// verifies it, and returns a handle to the package's metadata.
    fn get_cached_archive<T>(&self,
                             ui: &mut T,
                             package: &PackageIdentTarget)
                             -> Result<PackageArchive>
        where T: UIWriter
    {
        let fetch_artifact = || self.fetch_artifact(ui, package);
        if self.is_artifact_cached(package) {
            debug!("Found {} in artifact cache, skipping remote download",
                   package.ident);
            ui.status(Status::Skipping,
                      format!("because {} was found in downloads directory", package.ident))?;
        } else if let Err(err) = retry(delay::Fixed::from(RETRY_WAIT).take(RETRIES), fetch_artifact)
        {
            return Err(Error::DownloadFailed(format!("We tried {} times but \
                                                      could not download {}. \
                                                      Last error was: {}",
                                                     RETRIES, package, err)));
        }

        // At this point the artifact is in the cache...
        let mut artifact = PackageArchive::new(self.cached_artifact_path(package));
        self.verify_artifact(ui, package, &mut artifact)?;
        Ok(artifact)
    }

    // This function and it's sibling in install.rs deserve to be refactored to eke out commonality.
    /// Retrieve the identified package from the depot, ensuring that
    /// the artifact is cached locally.
    fn fetch_artifact<T>(&self, ui: &mut T, package: &PackageIdentTarget) -> Result<()>
        where T: UIWriter
    {
        ui.status(Status::Downloading, package)?;
        match self.api_client
                  .fetch_package((&package.ident, package.target),
                                 self.token,
                                 self.artifact_download_path,
                                 ui.progress())
        {
            Ok(_) => Ok(()),
            Err(api_client::Error::APIError(StatusCode::NOT_IMPLEMENTED, _)) => {
                println!("Host platform or architecture not supported by the targeted depot; \
                          skipping.");
                Ok(())
            }
            Err(e) => Err(Error::from(e)),
        }
    }

    fn fetch_origin_key<T>(&self,
                           ui: &mut T,
                           name_with_rev: &str,
                           token: Option<&str>)
                           -> Result<()>
        where T: UIWriter
    {
        ui.status(Status::Downloading,
                  format!("{} public origin key", &name_with_rev))?;
        let (name, rev) = parse_name_with_rev(&name_with_rev)?;
        self.api_client.fetch_origin_key(&name,
                                          &rev,
                                          token,
                                          self.key_download_path,
                                          ui.progress())?;
        ui.status(Status::Cached,
                  format!("{} public origin key", &name_with_rev))?;
        Ok(())
    }

    fn verify_artifact<T>(&self,
                          ui: &mut T,
                          package: &PackageIdentTarget,
                          artifact: &mut PackageArchive)
                          -> Result<()>
        where T: UIWriter
    {
        let artifact_ident = artifact.ident()?;
        if package.ident.as_ref() != &artifact_ident {
            return Err(Error::ArtifactIdentMismatch((artifact.file_name(),
                                                     artifact_ident.to_string(),
                                                     package.to_string())));
        }

        // Is this even possible? We specify the target in fetch_package above, so we should never
        // be given a
        let artifact_target = artifact.target()?;
        if package.target != artifact_target {
            debug!("Got wrong package target, expected {}, got {}",
                   artifact_target, package.target);
            return Err(Error::HabitatCore(hcore::Error::WrongActivePackageTarget(
                package.target,
                artifact_target,
            )));
        }

        let nwr = artifact::artifact_signer(&artifact.path)?;
        if SigKeyPair::get_public_key_path(&nwr, self.key_download_path).is_err() {
            ui.status(Status::Downloading,
                      format!("Public key for signer {:?}", nwr))?;
            self.fetch_origin_key(ui, &nwr, self.token)?;
        }

        if self.verify {
            ui.status(Status::Verifying, artifact.ident()?)?;
            artifact.verify(&self.key_download_path)?;
            debug!("Verified {} signed by {}", package, &nwr);
        }
        Ok(())
    }

    // This function and it's sibling in install.rs deserve to be refactored to eke out commonality.
    fn is_artifact_cached(&self, package: &PackageIdentTarget) -> bool {
        self.cached_artifact_path(package).is_file()
    }

    // This function and it's sibling in install.rs deserve to be refactored to eke out commonality.
    /// Returns the path to the location this package would exist at in
    /// the local package cache. It does not mean that the package is
    /// actually *in* the package cache, though.
    fn cached_artifact_path(&self, package: &PackageIdentTarget) -> PathBuf {
        self.artifact_download_path
            .join(package.archive_name().unwrap())
    }

    fn fetch_latest_package_in_channel_for(&self,
                                           ident: &PackageIdentTarget,
                                           channel: &ChannelIdent,
                                           token: Option<&str>)
                                           -> Result<Package> {
        let origin_package =
            self.api_client
                .show_package_metadata((&ident.ident, ident.target), channel, token)?;
        Ok(origin_package)
    }
}

/// The cache_*_path functions in fs don't let you override a path base with Some(base)
/// This is a helper until we get that sorted out.
fn path_helper(base: Option<&PathBuf>, extension: &str, default_path: &PathBuf) -> PathBuf {
    base.map_or(default_path.to_path_buf(), |x| x.join(extension))
}
