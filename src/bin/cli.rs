#![feature(setgroups)]
#![feature(entry_insert)]
extern crate core;

use std::env;
use std::fs;
use std::fmt;
use std::fs::{File, symlink_metadata};
use std::os::unix::fs::MetadataExt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Child, Output, ExitStatus};
use std::os::unix::process::CommandExt;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt::Formatter;
use std::ops::Index;
use dioxus::html::path;
use flate2::read::GzDecoder;
use regex::Regex;
use rustix::path::Arg;
use rustix::process;
use rustix::process::geteuid;
use serde::Deserialize;
use tar::{Archive};
use users::{get_effective_uid, get_user_by_name, get_user_groups};

// TODO: Test
fn run_occ_command_blocking(ncp_config: &NcpConfig, args: Vec<&str>) -> Result<Output, String>{
    let occ_path = ncp_config.nc_www_directory.join("occ");
    if !occ_path.is_file() {
        return Err(format!("Error executing occ: Could not find occ at {}",
                           occ_path.to_str().unwrap_or("unknown")))
    }
    // Dynamically detecting the owner is probably a bad idea,
    // because it would enable a privilege escalation attack
    // let occ_owner = occ_path.metadata().map_err(|e| e.to_string())?.st_uid();

    let mut occ_command = vec!(occ_path.to_str().unwrap());
    occ_command.extend(args);


    let www_data_user = get_user_by_name("www-data")
        .ok_or("Could not retrieve uid of user www-data")?;
    let groups: Vec<u32> = match www_data_user.groups() {
        None => vec!(),
        Some(gs) => gs.iter().map(|g| g.gid()).collect::<Vec<u32>>()
    };
    let mut cmd = Command::new("php");
    let cmd1 = cmd.uid(www_data_user.uid())
        .gid(www_data_user.primary_group_id())
        .groups(groups.as_slice())
        .args(occ_command);
    println!("running occ command: {} {}",
             &cmd1.get_program().as_str().unwrap(),
             &cmd1.get_args().map(|s| s.to_str().unwrap()).collect::<Vec<&str>>().join(" "));
    cmd1.output()
        .map_err(|e| e.to_string())
}

fn get_nc_config_value(ncp_config: &NcpConfig, key: &str, system_context: bool) -> Result<String, String>{
    let context_str = match system_context {
        true => "system",
        false => "app",
    };
    let result = run_occ_command_blocking(
        ncp_config,
        vec![format!("config:{}:get", context_str).as_str(), key])?;
    match result.status.success() {
        true => match String::from_utf8(result.stdout) {
            Ok(s) => Ok(s.trim_end_matches("\n").into()),
            Err(e) => Err(e.to_string())
        },
        false => Err(format!("Could not retrieve Nextcloud config value: {}/{}",
                             String::from_utf8(result.stdout)
                                 .unwrap_or("unknown reason".to_string()),
                             String::from_utf8(result.stderr)
                                 .unwrap_or("unknown reason".to_string())))
    }
}

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

    fn default() -> NcpConfig {
        return NcpConfig{
            nc_version: [0, 0, 0],
            nc_www_directory: PathBuf::from("/var/www/nextcloud"),
            nc_data_directory: PathBuf::from("/opt/ncdata/data"),
            nc_maintenance_mode: false,
            ncp_data_volume: PathBuf::from("/opt/ncdata"),
            ncp_version: [0, 0, 0],
        }
    }

    fn detect_system_config(force: bool) -> Result<NcpConfig, String> {
        let mut config = NcpConfig::default();

        let ncp_cfg_path = PathBuf::from("/usr/local/etc/ncp.cfg");
        if ncp_cfg_path.is_file() {
            if let Ok(f) = File::open(ncp_cfg_path) {
                if let Ok(ncp_cfg) = serde_json::from_reader::<File, NcpCfgJsonModel>(f) {
                    if let Ok(nc_version_num) = ncp_cfg.nextcloud_version.trim()
                        .split(".").into_iter()
                        .take(3)
                        .map(|i| i.parse::<u32>())
                        .collect::<Result<Vec<u32>, _>>() {

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

        match get_nc_config_value(&config, "datadirectory", true) {
            Ok(nc_datadir) => config.nc_data_directory = PathBuf::from(nc_datadir),
            Err(e) => if !force {
                return Err(e)
            }
        }

        match get_nc_config_value(&config, "maintenance", true) {
            Ok(nc_maintenance) => config.nc_maintenance_mode = nc_maintenance == "true",
            Err(e) => if !force {
                return Err(e)
            }
        }

        if config.nc_data_directory.exists() {
            let canonicalized = config.nc_data_directory.canonicalize()
                .map_err(|e| e.to_string())?;

            let pathinfo = symlink_metadata(&canonicalized)
                .map_err(|e| e.to_string())?;
            let datadir_dev = pathinfo.dev();
            config.ncp_data_volume = match canonicalized.parent() {
                None => {
                    config.nc_data_directory.clone()
                }
                Some(parent) => {
                    let pathinfo2 = symlink_metadata(parent)
                        .map_err(|e| e.to_string())?;
                    match pathinfo2.dev() == datadir_dev {
                        true => parent.to_owned(),
                        false => config.nc_data_directory.clone()
                    }
                }
            };
        }

        match fs::read_to_string("/usr/local/etc/ncp-version") {
            Err(e) => if !force {
                return Err(e.to_string())
            },
            Ok(ncp_version_str) => match ncp_version_str
                .trim()
                .replace("v", "")
                .splitn(3, ".")
                .map(|i| i.parse::<u32>())
                .collect::<Result<Vec<u32>, _>>() {
                Ok(ncp_version) => {
                    config.ncp_version.copy_from_slice(&ncp_version);
                },
                Err(e) => if !force {
                    return Err(e.to_string())
                }
            }

        }

        Ok(config)
    }

}

#[derive(Debug)]
pub struct RestoreConfig {
    source_ncp_config: NcpConfig,
    target_ncp_config: NcpConfig,
    restore_nextcloud: bool,
    restore_db: bool,
    restore_files: bool,
    restore_ncp_config: bool
}

impl RestoreConfig {
    fn from_backup(backup: Backup, system_config: Option<NcpConfig>, overwrite: Option<RestoreConfig>) -> Result<RestoreConfig, String> {
        let capabilities = backup.get_restore_capabilities()?;
        
    }
}

pub trait BackupProviderConfig {
    fn validate(&self) -> bool;
    fn get_restore_capabilities(&self, backup: &str) -> Result<RestoreCapabilities, String>;
    
    fn get_ncp_system_config(&self, backup: &str) -> Option<NcpConfig>;

    fn restore(&self, backup: &str, ncp_config: NcpConfig, restore_config: RestoreConfig) -> Result<(), String>;

    fn scan_backups(&self, cache: &mut BackupCache, rescan: bool) -> Result<(), String>;

    fn list_backups(&self, cache: &BackupCache) -> Vec<BackupInfo>;
}

#[derive(Debug, Clone)]
struct RestoreCapabilities {
    db: bool,
    nextcloud: bool,
    files: bool,
    ncp_config: bool
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
struct BtrfsSnapshotConfig {

}

enum BackupProvider {
    Tarball(TarballBackupConfig, BackupCache)
}
#[derive(Eq, PartialEq, Hash, Clone)]
struct TarballBackupConfig {
    path: PathBuf,
}

impl BackupProvider {
    fn from_tarball_backup_directory(backups_path: &str) -> BackupProvider {
        BackupProvider::Tarball(TarballBackupConfig{path: PathBuf::from(backups_path)}, BackupCache::new())
    }


    fn validate(&self) -> bool {
        match self {
            BackupProvider::Tarball(cfg, _) => cfg.validate(),
        }
    }

    fn get_restore_capabilities(&self, backup: &str) -> Result<RestoreCapabilities, String> {
        match self {
            BackupProvider::Tarball(cfg, _) => cfg.get_restore_capabilities(backup)
        }
    }

    fn restore(&self, backup: &str, ncp_config: NcpConfig, restore_config: RestoreConfig) -> Result<(), String> {
        match self { BackupProvider::Tarball(cfg, _) => cfg.restore(backup, ncp_config, restore_config) }
    }

    fn scan_backups(&mut self, rescan: bool) -> Result<(), String> {
        match self { BackupProvider::Tarball(cfg, cache) => cfg.scan_backups(cache, rescan) }
    }

    fn list_backups(&self) -> Vec<BackupInfo> {
        match self { BackupProvider::Tarball(cfg, cache) => cfg.list_backups(cache) }
    }
}

impl fmt::Debug for TarballBackupConfig {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "TarballBackupConfig{{ path: {:?} }}", self.path)
    }
}

fn open_tarball(tar_path: &Path) -> Result<Box<dyn Read>, String> {
    let f = File::open(tar_path).map_err(|e| e.to_string())?;
    let is_gz = tar_path.extension()
        .ok_or("Failed to parse backup file name")?
        .to_str().is_some_and(|ext| ext == "gz");
    return if is_gz {
        Ok(Box::new(GzDecoder::new(f)))
    } else {
        Ok(Box::new(f))
    };
}

impl BackupProviderConfig for TarballBackupConfig {
    fn validate(&self) -> bool {
        return true
    }

    fn get_restore_capabilities(&self, backup: &str) -> Result<RestoreCapabilities, String> {
        let backup_path = PathBuf::from(backup);

        let re_db = Regex::new(r"^nextcloud-sqlbkp_.*\.(bak|sql)$").
            map_err(|e| e.to_string())?;
        let re_files = Regex::new(r"^[^/]*/.ocdata$").
            map_err(|e| e.to_string())?;
        let re_nextcloud = Regex::new(r"^nextcloud/$").
            map_err(|e| e.to_string())?;

        if !backup_path.is_file() {
            return Err("Could not open backup: No such file".to_string())
        }
        let read = open_tarball(&backup_path)?;
        let mut archive =  Archive::new(read);
        let mut caps = RestoreCapabilities{
            db: false,
            files: false,
            nextcloud: false,
            ncp_config: false
        };
        for entry in archive.entries()
            .map_err(|e| e.to_string())?
            .filter_map(|e| match e {
                Ok(v) => Some(v),
                Err(s) => {
                    println!("{:?}", s);
                    None
                }
            })
            .map(|entry| -> Result<PathBuf, Box<String>> {
                Ok(entry.path().map_err(|e| e.to_string())?.into_owned())
            }).filter_map(|e| e.ok()) {
            
            if let Some(s) = entry.to_str() {
                if !caps.db && re_db.is_match(s) {
                    caps.db = true
                } else if !caps.files && re_files.is_match(s) {
                    caps.files = true
                } else if !caps.nextcloud && re_nextcloud.is_match(s) {
                    caps.nextcloud = true
                }
                if caps.db && caps.files && caps.nextcloud {
                    break;
                }
            }
        }

        if !(caps.db || caps.files || caps.nextcloud || caps.ncp_config) {
            return Err("No recoverable data found in backup".to_string())
        }
        return Ok(caps)
    }

    fn get_ncp_system_config(&self, backup: &str) -> Option<NcpConfig> {
        let bkp_path = PathBuf::from(backup);
        let mut arch = match open_tarball(&bkp_path) {
            Ok(read) => Archive::new(read),
            Err(_) => return None,
        };
        let ncp_cfg_results = arch.entries().ok()?.filter_map(|e| match e {
            Ok(entry) => match &entry.path().ok()?.ends_with("ncp.cfg") {
                true => Some(entry),
                false => None
            }
            Err(_) => None
        }).map(|mut entry| -> Result<String, String> {
            let mut buffer = String::new();
            entry.read_to_string(&mut buffer).map_err(|_| "Failed to read ncp.cfg to string")?;
            return Ok(buffer);
        }).collect::<Result<Vec<String>, String>>().ok()?;
        if ncp_cfg_results.len() != 1 {
            return None
        }
        let ncp_cfg = ncp_cfg_results[0].to_string();
    }

    // todo refactor to use some sort of restore process multistep engine
    fn restore(&self, backup_path: &str, ncp_config: NcpConfig, restore_config: RestoreConfig) -> Result<(), String> {
        todo!();
    }

    fn scan_backups(&self, cache: &mut BackupCache, rescan: bool) -> Result<(), String> {
        let files = fs::read_dir(&self.path).map_err(|e| e.to_string())?;
        for backup in files {
            if let Ok(bkp) = backup {
                if let Some(bkp_str) = bkp.path().to_str() {
                    let index = Backup::Legacy(self.clone(), bkp_str.to_string());
                    if cache.contains_key(&index) && !rescan {
                        continue
                    }
                    let mut val = match self.get_restore_capabilities(bkp_str) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            println!("{:?}", e);
                            None
                        }
                    };
                    // let _ = cache.get_mut(&index).insert(&mut val);
                    cache.entry(index).insert_entry(val);
                }
            }
        }
        Ok(())
    }

    fn list_backups(&self, cache: &BackupCache) -> Vec<BackupInfo> {
        cache.keys().map(|k| BackupInfo{
            backup: k.clone(),
            capabilities: cache.get(k).unwrap_or(&None).clone()
        }).collect::<Vec<BackupInfo>>()
    }
}

#[derive(Debug)]
struct BackupInfo {
    backup: Backup,
    capabilities: Option<RestoreCapabilities>,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
enum Backup {
    Kopia(KopiaConfig, String),
    Btrfs(BtrfsSnapshotConfig, String),
    Legacy(TarballBackupConfig, String),
}

impl Backup {
    fn get_restore_capabilities(&self) -> Result<RestoreCapabilities, String> {
        match self {
            Backup::Legacy(config, s) => config.get_restore_capabilities(s),
            _ => Err("Not implemented".to_string())
        }
    }
    
    fn get_ncp_system_config(&self) -> Result<NcpConfig, String> {
        match self {
            Backup::Legacy(config, s) => config.get_ncp_system_config(s),
            _ => Err("Not implemented".to_string())
        }
    }
}

type BackupCache = HashMap<Backup, Option<RestoreCapabilities>>;


// impl BackupProvider {
//     fn validate(&self) -> bool{
//         match self {
//             BackupProvider::Kopia(config) => {
//
//             }
//             BackupProvider::Btrfs(config) => {
//
//             }
//             BackupProvider::Legacy(config) => {
//                 return config.path.is_file() && {
//                     match File::open(config.path) {
//
//                     }
//                 }
//
//             }
//         }
//     }
// }
//
// fn restoreBackup(provider: BackupProvider, backup_id: String) {
//
// }

fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(geteuid().is_root(), "ERROR: Must be run as root (try sudo)");
    println!("{:?}", NcpConfig::detect_system_config(false).unwrap());

    let mut backup_provider = BackupProvider::from_tarball_backup_directory(args[1].as_str());

    backup_provider.scan_backups(false).unwrap();
    println!("Tarball Backups:\n{}",
        backup_provider.list_backups().iter().map(|b| format!("- {:?}", b)).collect::<Vec<String>>().join("\n"))
}