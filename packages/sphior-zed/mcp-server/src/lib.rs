//! SPHIOR CODE MCP server for Zed.
//!
//! Starts `sphior-code-mcp` (npm) with Zed's Node.js runtime. Zed's extension rules forbid
//! bundling the server, so it is installed from npm on first use and updated when a newer
//! version is published. Without an API key the server runs in local mode: it scans the
//! workspace with the bundled deterministic engine and source code never leaves the machine.

use std::{collections::HashMap, env, fs};

use serde::Deserialize;
use zed_extension_api::{
    self as zed, serde_json, settings::ContextServerSettings, ContextServerConfiguration,
    ContextServerId, Project, Result,
};

const PACKAGE: &str = "sphior-code-mcp";
const SERVER_PATH: &str = "node_modules/sphior-code-mcp/bin/sphior-code-mcp.js";

/// Optional settings under `context_servers.sphior-code.settings`.
#[derive(Debug, Default, Deserialize)]
struct Settings {
    /// Connects the account tools to SPHIOR. Keys start with `sk_live_`.
    sphior_api_key: Option<String>,
}

struct SphiorCodeMcp {
    did_find_server: bool,
}

impl SphiorCodeMcp {
    fn server_exists() -> bool {
        fs::metadata(SERVER_PATH).is_ok_and(|m| m.is_file())
    }

    fn server_script_path(&mut self) -> Result<String> {
        let exists = Self::server_exists();
        if self.did_find_server && exists {
            return Ok(SERVER_PATH.to_string());
        }

        let latest = zed::npm_package_latest_version(PACKAGE)?;
        if !exists
            || zed::npm_package_installed_version(PACKAGE)?.as_deref() != Some(latest.as_str())
        {
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

impl zed::Extension for SphiorCodeMcp {
    fn new() -> Self {
        Self {
            did_find_server: false,
        }
    }

    fn context_server_command(
        &mut self,
        _context_server_id: &ContextServerId,
        project: &Project,
    ) -> Result<zed::Command> {
        let script = env::current_dir()
            .map_err(|e| format!("could not resolve the extension directory: {e}"))?
            .join(self.server_script_path()?);

        let settings = ContextServerSettings::for_project("sphior-code", project)?;
        let settings: Settings = match settings.settings {
            Some(value) => serde_json::from_value(value).map_err(|e| e.to_string())?,
            None => Settings::default(),
        };

        let mut env = HashMap::new();
        if let Some(key) = settings.sphior_api_key.filter(|k| !k.trim().is_empty()) {
            env.insert("SPHIOR_API_KEY".to_string(), key);
        }

        Ok(zed::Command {
            command: zed::node_binary_path()?,
            args: vec![script.to_string_lossy().into_owned()],
            env: env.into_iter().collect(),
        })
    }

    fn context_server_configuration(
        &mut self,
        _context_server_id: &ContextServerId,
        _project: &Project,
    ) -> Result<Option<ContextServerConfiguration>> {
        let installation_instructions =
            include_str!("../configuration/installation_instructions.md").to_string();
        let default_settings = include_str!("../configuration/default_settings.jsonc").to_string();
        let settings_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "sphior_api_key": {
                    "type": "string",
                    "description": "Optional. Connects the account tools to SPHIOR. Keys start with sk_live_. Leave empty for local mode."
                }
            },
            "additionalProperties": false
        })
        .to_string();

        Ok(Some(ContextServerConfiguration {
            installation_instructions,
            default_settings,
            settings_schema,
        }))
    }
}

zed::register_extension!(SphiorCodeMcp);
