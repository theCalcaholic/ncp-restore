#![feature(setgroups)]
#![feature(entry_insert)]

pub mod tarball;
pub mod occ;

use std::{fs};
use std::collections::HashMap;
use std::fs::{File, symlink_metadata};
use std::path::{PathBuf};
use std::os::unix::fs::MetadataExt;
use serde::Deserialize;
use crate::occ::get_nc_config_value;
use crate::tarball::TarballBackupConfig;

#[derive(Debug, Deserialize)]
pub struct NcpCfgJsonModel {
    nextcloud_version: String,
    php_version: String,
    release: String,
    datadir: String,
}

#[derive(Debug)]
pub struct NcpConfig {
    nc_version: [u32; 3],
    nc_www_directory: PathBuf,
    nc_data_directory: PathBuf,
    nc_maintenance_mode: bool,
    ncp_data_volume: PathBuf,
    ncp_version: [u32; 3],
}

impl NcpConfig {
    pub fn default() -> NcpConfig {
        return NcpConfig {
            nc_version: [0, 0, 0],
            nc_www_directory: PathBuf::from("/var/www/nextcloud"),
            nc_data_directory: PathBuf::from("/opt/ncdata/data"),
            nc_maintenance_mode: false,
            ncp_data_volume: PathBuf::from("/opt/ncdata"),
            ncp_version: [0, 0, 0],
        };
    }

    pub fn detect_system_config(force: bool) -> Result<NcpConfig, String> {
        let mut config = NcpConfig::default();

        let ncp_cfg_path = PathBuf::from("/usr/local/etc/ncp.cfg");
        if ncp_cfg_path.is_file() {
            if let Ok(f) = File::open(ncp_cfg_path) {
                if let Ok(ncp_cfg) = serde_json::from_reader::<File, NcpCfgJsonModel>(f) {
                    if let Ok(nc_version_num) = ncp_cfg
                        .nextcloud_version
                        .trim()
                        .split(".")
                        .into_iter()
                        .take(3)
                        .map(|i| i.parse::<u32>())
                        .collect::<Result<Vec<u32>, _>>()
                    {
                        config.nc_version.copy_from_slice(&nc_version_num);
                    }
                }
            }
        }
        // if let Ok(nc_version_str) = get_nc_config_value(&config, "version", true) {
        //     if let Ok(nc_version_num) = nc_version_str.trim()
        //         .split(".").into_iter()
        //         .take(3)
        //         .map(|i| i.parse::<u32>())
        //         .collect::<Result<Vec<u32>, _>>() {
        //
        //         config.nc_version.copy_from_slice(&nc_version_num);
        //     }
        // }

        match get_nc_config_value(&config, vec!["datadirectory"], true) {
            Ok(nc_datadir) => config.nc_data_directory = PathBuf::from(nc_datadir),
            Err(e) => {
                if !force {
                    return Err(e);
                }
            }
        }

        match get_nc_config_value(&config, vec!["maintenance"], true) {
            Ok(nc_maintenance) => config.nc_maintenance_mode = nc_maintenance == "true",
            Err(e) => {
                if !force {
                    return Err(e);
                }
            }
        }

        if config.nc_data_directory.exists() {
            let canonicalized = config
                .nc_data_directory
                .canonicalize()
                .map_err(|e| e.to_string())?;

            let pathinfo = symlink_metadata(&canonicalized).map_err(|e| e.to_string())?;
            let datadir_dev = pathinfo.dev();
            config.ncp_data_volume = match canonicalized.parent() {
                None => config.nc_data_directory.clone(),
                Some(parent) => {
                    let pathinfo2 = symlink_metadata(parent).map_err(|e| e.to_string())?;
                    match pathinfo2.dev() == datadir_dev {
                        true => parent.to_owned(),
                        false => config.nc_data_directory.clone(),
                    }
                }
            };
        }

        match fs::read_to_string("/usr/local/etc/ncp-version") {
            Err(e) => {
                if !force {
                    return Err(e.to_string());
                }
            }
            Ok(ncp_version_str) => match ncp_version_str
                .trim()
                .replace("v", "")
                .splitn(3, ".")
                .map(|i| i.parse::<u32>())
                .collect::<Result<Vec<u32>, _>>()
            {
                Ok(ncp_version) => {
                    config.ncp_version.copy_from_slice(&ncp_version);
                }
                Err(e) => {
                    if !force {
                        return Err(e.to_string());
                    }
                }
            },
        }

        Ok(config)
    }
}

#[derive(Debug)]
pub struct RestoreConfig {
    pub source_ncp_config: Option<NcpConfig>,
    pub target_ncp_config: NcpConfig,
    pub restore_nextcloud: bool,
    pub restore_db: bool,
    pub restore_files: bool,
    pub restore_ncp_config: bool,
}

impl RestoreConfig {
    fn from_backup(
        backup: Backup,
        system_config: Option<NcpConfig>,
        overwrite: Option<RestoreConfig>,
    ) -> Result<RestoreConfig, String> {
        let capabilities = backup.get_restore_capabilities()?;
        // let source_config = match backup {
        //     _ => todo!("Not yet implemented"),
        //     Backup::Legacy(cfg, bkp) => cfg.get_ncp_system_config(&bkp)
        // }
        Ok(RestoreConfig {
            restore_db: capabilities.db,
            restore_files: capabilities.files,
            restore_ncp_config: capabilities.ncp_config,
            restore_nextcloud: capabilities.nextcloud,
            source_ncp_config: None,
            target_ncp_config: NcpConfig::detect_system_config(true)
                .unwrap_or(NcpConfig::default()),
        })
    }
}

pub trait BackupProviderConfig {
    fn validate(&self) -> bool;
    fn get_restore_capabilities(&self, backup: &str) -> Result<RestoreCapabilities, String>;

    fn get_ncp_system_config(&self, backup: &str) -> Option<NcpConfig>;

    fn restore(&self, backup: &str, restore_config: RestoreConfig) -> Result<(Option<PathBuf>, Option<PathBuf>), String>;

    fn scan_backups(&self, cache: &mut BackupCache, rescan: bool) -> Result<(), String>;

    fn list_backups(&self, cache: &BackupCache) -> Vec<BackupInfo>;

    fn backup_info(&self, cache: &mut BackupCache, backup: &str, rescan: bool) -> Result<BackupInfo, String>;
}

#[derive(Debug, Clone)]
pub struct RestoreCapabilities {
    pub db: bool,
    pub nextcloud: bool,
    pub files: bool,
    pub ncp_config: bool,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct KopiaConfig {}

// impl BackupProvider for KopiaConfig {
//     fn can_restore(&self, backup_id: String) -> bool {
//
//     }
//     fn validate_config(&self) -> bool {
//
//     }
// }

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct BtrfsSnapshotConfig {}

pub enum BackupProvider {
    Tarball(TarballBackupConfig, BackupCache),
}

impl BackupProvider {
    pub fn from_tarball_backup_directory(backups_path: &str) -> BackupProvider {
        BackupProvider::Tarball(
            TarballBackupConfig {
                path: Some(PathBuf::from(backups_path)),
            },
            BackupCache::new(),
        )
    }

    pub fn validate(&self) -> bool {
        match self {
            BackupProvider::Tarball(cfg, _) => cfg.validate(),
        }
    }

    pub fn get_restore_capabilities(&self, backup: &str) -> Result<RestoreCapabilities, String> {
        match self {
            BackupProvider::Tarball(cfg, _) => cfg.get_restore_capabilities(backup),
        }
    }

    pub fn restore(&self, backup: &str, restore_config: RestoreConfig) -> Result<(Option<PathBuf>, Option<PathBuf>), String> {
        match self {
            BackupProvider::Tarball(cfg, _) => cfg.restore(backup, restore_config),
        }
    }

    pub fn scan_backups(&mut self, rescan: bool) -> Result<(), String> {
        match self {
            BackupProvider::Tarball(cfg, cache) => cfg.scan_backups(cache, rescan),
        }
    }

    pub fn show_backup(&mut self, backup: &str, rescan: bool) -> Result<BackupInfo, String> {
        match self {
            BackupProvider::Tarball(cfg, cache) => {
                cfg.backup_info(cache, backup, rescan)
            }
        }
    }

    pub fn list_backups(&self) -> Vec<BackupInfo> {
        match self {
            BackupProvider::Tarball(cfg, cache) => cfg.list_backups(cache),
        }
    }
}

#[derive(Debug)]
pub struct BackupInfo {
    backup: Backup,
    capabilities: Option<RestoreCapabilities>,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum Backup {
    Kopia(KopiaConfig, String),
    Btrfs(BtrfsSnapshotConfig, String),
    Legacy(TarballBackupConfig, String),
}

impl Backup {
    fn get_restore_capabilities(&self) -> Result<RestoreCapabilities, String> {
        match self {
            Backup::Legacy(config, s) => config.get_restore_capabilities(s),
            _ => Err("Not implemented".to_string()),
        }
    }

    fn get_ncp_system_config(&self) -> Option<NcpConfig> {
        match self {
            Backup::Legacy(config, s) => config.get_ncp_system_config(s),
            _ => todo!("Not yet implemented"),
        }
    }
}

type BackupCache = HashMap<Backup, Option<RestoreCapabilities>>;
