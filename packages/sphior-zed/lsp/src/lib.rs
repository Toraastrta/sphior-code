//! SPHIOR CODE language server for Zed.
//!
//! Runs the language server shipped in the `@sphior/scan` npm package (`dist/server.cjs`) with
//! Zed's own Node.js runtime. Zed's extension rules forbid bundling the server, so it is
//! installed from npm on first use and updated when a newer version is published.
//! The server analyses open files locally; no source code leaves the machine.

use std::{env, fs};
use zed_extension_api::{self as zed, LanguageServerId, Result};

const PACKAGE: &str = "@sphior/scan";
const SERVER_PATH: &str = "node_modules/@sphior/scan/dist/server.cjs";

struct SphiorCode {
    /// Set once the server script is known to be installed in this session.
    did_find_server: bool,
}

impl SphiorCode {
    fn server_exists() -> bool {
        fs::metadata(SERVER_PATH).is_ok_and(|m| m.is_file())
    }

    /// Installs or updates `@sphior/scan` when needed and returns the server script path,
    /// relative to the extension's working directory.
    fn server_script_path(&mut self, id: &LanguageServerId) -> Result<String> {
        let exists = Self::server_exists();
        if self.did_find_server && exists {
            return Ok(SERVER_PATH.to_string());
        }

        zed::set_language_server_installation_status(
            id,
            &zed::LanguageServerInstallationStatus::CheckingForUpdate,
        );
        let latest = zed::npm_package_latest_version(PACKAGE)?;

        if !exists
            || zed::npm_package_installed_version(PACKAGE)?.as_deref() != Some(latest.as_str())
        {
            zed::set_language_server_installation_status(
                id,
                &zed::LanguageServerInstallationStatus::Downloading,
            );
            match zed::npm_install_package(PACKAGE, &latest) {
                Ok(()) if Self::server_exists() => {}
                Ok(()) => {
                    return Err(format!(
                        "installed {PACKAGE}@{latest}, but {SERVER_PATH} was not found"
                    ))
                }
                // An update that fails is not fatal while a previous version is still installed.
                Err(error) if !exists => return Err(error),
                Err(_) => {}
            }
        }

        self.did_find_server = true;
        Ok(SERVER_PATH.to_string())
    }
}

impl zed::Extension for SphiorCode {
    fn new() -> Self {
        Self {
            did_find_server: false,
        }
    }

    fn language_server_command(
        &mut self,
        language_server_id: &LanguageServerId,
        _worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        let script = self.server_script_path(language_server_id)?;
        let script = env::current_dir()
            .map_err(|e| format!("could not resolve the extension directory: {e}"))?
            .join(script);
        Ok(zed::Command {
            command: zed::node_binary_path()?,
            args: vec![script.to_string_lossy().into_owned(), "--stdio".to_string()],
            env: Default::default(),
        })
    }
}

zed::register_extension!(SphiorCode);
