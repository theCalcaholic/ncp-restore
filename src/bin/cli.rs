#![feature(setgroups)]
#![feature(entry_insert)]
extern crate core;

use flate2::read::GzDecoder;
use rand::distributions::{Alphanumeric, DistString};
use regex::{Regex};
use rustix::path::Arg;
use rustix::process::geteuid;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fmt::Formatter;
use std::fs;
use std::fs::{symlink_metadata, File};
use std::io::{Read, Write};
use std::ops::Index;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use clap::{Parser, Subcommand};
use clap::builder::Str;
use tar::{Archive, Entry};
use users::{get_user_by_name};

// TODO: Test
fn run_occ_command_blocking(ncp_config: &NcpConfig, args: Vec<&str>) -> Result<Output, String> {
    let occ_path = ncp_config.nc_www_directory.join("occ");
    if !occ_path.is_file() {
        return Err(format!(
            "Error executing occ: Could not find occ at {}",
            occ_path.to_str().unwrap_or("unknown")
        ));
    }
    // Dynamically detecting the owner is probably a bad idea,
    // because it would enable a privilege escalation attack
    // let occ_owner = occ_path.metadata().map_err(|e| e.to_string())?.st_uid();

    let mut occ_command = vec![occ_path.to_str().unwrap()];
    occ_command.extend(args);

    let www_data_user =
        get_user_by_name("www-data").ok_or("Could not retrieve uid of user www-data")?;
    let groups: Vec<u32> = match www_data_user.groups() {
        None => vec![],
        Some(gs) => gs.iter().map(|g| g.gid()).collect::<Vec<u32>>(),
    };
    let mut cmd = Command::new("php");
    let cmd1 = cmd
        .uid(www_data_user.uid())
        .gid(www_data_user.primary_group_id())
        .groups(groups.as_slice())
        .args(occ_command);
    println!(
        "running occ command: {} {} ({} args)",
        &cmd1.get_program().as_str().unwrap(),
        &cmd1
            .get_args()
            .map(|s| s.to_str().unwrap())
            .collect::<Vec<&str>>()
            .join(" "),
        &cmd1.get_args().len()
    );
    cmd1.output().map_err(|e| e.to_string())
}

fn set_nc_config_value(
    ncp_config: &NcpConfig,
    key: Vec<&str>,
    value: &str,
    system_context: bool,
) -> Result<String, String> {
    let context_str = match system_context {
        true => "system",
        false => "app",
    };
    let result = run_occ_command_blocking(
        ncp_config,
        vec![format!("config:{}:set", context_str).as_str()]
            .into_iter()
            .chain(key)
            .chain(["--value", value])
            .collect(),
    )?;
    match result.status.success() {
        true => match String::from_utf8(result.stdout) {
            Ok(s) => Ok(s.trim_end_matches("\n").into()),
            Err(e) => Err(e.to_string()),
        },
        false => Err(format!(
            "Could not set Nextcloud config value: {}/{}",
            String::from_utf8(result.stdout).unwrap_or("unknown reason".to_string()),
            String::from_utf8(result.stderr).unwrap_or("unknown reason".to_string())
        )),
    }
}

// enum NC_CONFIG_KEY {
//     Nested(Vec<String>),
//     Simple(String)
// }

fn get_nc_config_value(
    ncp_config: &NcpConfig,
    key: Vec<&str>,
    system_context: bool,
) -> Result<String, String> {
    let context_str = match system_context {
        true => "system",
        false => "app",
    };
    let result = run_occ_command_blocking(
        ncp_config,
        vec![format!("config:{}:get", context_str).as_str()]
            .into_iter()
            .chain(key)
            .collect(),
    )?;
    match result.status.success() {
        true => match String::from_utf8(result.stdout) {
            Ok(s) => Ok(s.trim_end_matches("\n").into()),
            Err(e) => Err(e.to_string()),
        },
        false => Err(format!(
            "Could not retrieve Nextcloud config value: {}/{}",
            String::from_utf8(result.stdout).unwrap_or("unknown reason".to_string()),
            String::from_utf8(result.stderr).unwrap_or("unknown reason".to_string())
        )),
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
        return NcpConfig {
            nc_version: [0, 0, 0],
            nc_www_directory: PathBuf::from("/var/www/nextcloud"),
            nc_data_directory: PathBuf::from("/opt/ncdata/data"),
            nc_maintenance_mode: false,
            ncp_data_volume: PathBuf::from("/opt/ncdata"),
            ncp_version: [0, 0, 0],
        };
    }

    fn detect_system_config(force: bool) -> Result<NcpConfig, String> {
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
    source_ncp_config: Option<NcpConfig>,
    target_ncp_config: NcpConfig,
    restore_nextcloud: bool,
    restore_db: bool,
    restore_files: bool,
    restore_ncp_config: bool,
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
    db: bool,
    nextcloud: bool,
    files: bool,
    ncp_config: bool,
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

enum BackupProvider {
    Tarball(TarballBackupConfig, BackupCache),
}
#[derive(Eq, PartialEq, Hash, Clone)]
struct TarballBackupConfig {
    path: PathBuf,
}

impl BackupProvider {
    fn from_tarball_backup_directory(backups_path: &str) -> BackupProvider {
        BackupProvider::Tarball(
            TarballBackupConfig {
                path: PathBuf::from(backups_path),
            },
            BackupCache::new(),
        )
    }

    fn validate(&self) -> bool {
        match self {
            BackupProvider::Tarball(cfg, _) => cfg.validate(),
        }
    }

    fn get_restore_capabilities(&self, backup: &str) -> Result<RestoreCapabilities, String> {
        match self {
            BackupProvider::Tarball(cfg, _) => cfg.get_restore_capabilities(backup),
        }
    }

    fn restore(&self, backup: &str, restore_config: RestoreConfig) -> Result<(Option<PathBuf>, Option<PathBuf>), String> {
        match self {
            BackupProvider::Tarball(cfg, _) => cfg.restore(backup, restore_config),
        }
    }

    fn scan_backups(&mut self, rescan: bool) -> Result<(), String> {
        match self {
            BackupProvider::Tarball(cfg, cache) => cfg.scan_backups(cache, rescan),
        }
    }

    fn show_backup(&mut self, backup: &str, rescan: bool) -> Result<BackupInfo, String> {
        match self {
            BackupProvider::Tarball(cfg, cache) => {
                cfg.backup_info(cache, backup, rescan)
            }
        }
    }

    fn list_backups(&self) -> Vec<BackupInfo> {
        match self {
            BackupProvider::Tarball(cfg, cache) => cfg.list_backups(cache),
        }
    }
}

impl fmt::Debug for TarballBackupConfig {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "TarballBackupConfig{{ path: {:?} }}", self.path)
    }
}

fn open_tarball(tar_path: &Path) -> Result<Box<dyn Read>, String> {
    let f = File::open(tar_path).map_err(|e| e.to_string())?;
    let is_gz = tar_path
        .extension()
        .ok_or("Failed to parse backup file name")?
        .to_str()
        .is_some_and(|ext| ext == "gz");
    if is_gz {
        Ok(Box::new(GzDecoder::new(f)))
    } else {
        Ok(Box::new(f))
    }
}

impl TarballBackupConfig {
    fn restore_tarball_to(
        &self,
        tarball_path: &str,
        to_path: &Path,
        filter_prefix: &str,
        strip_prefix: &str,
        owner: Option<(u32, u32)>,
    ) -> Result<Option<PathBuf>, String> {
        let mut tarball = Archive::new(open_tarball(&PathBuf::from(tarball_path))?);
        let nc_temporary_backup_path = to_path.with_file_name(format!(
            "{}_{}_bkp",
            match to_path.file_name() {
                Some(s) => s.to_str().unwrap_or("nextcloud"),
                None => "nextcloud",
            },
            Alphanumeric.sample_string(&mut rand::thread_rng(), 8)
        ));
        if to_path.exists() {
            if let Err(e) = fs::rename(to_path, &nc_temporary_backup_path) {
                return Err(e.to_string());
            }
        } else {
            fs::create_dir_all(to_path).map_err(|e| e.to_string())?;
        }
        let mut io_lock = std::io::stderr().lock();
        writeln!(io_lock, "Extracting {:?} to {:?}...", &tarball_path, to_path).unwrap();
        tarball
            .entries()
            .map_err(|e| e.to_string())?
            .filter_map(|e| {
                match e {
                    Err(_) => None,
                    Ok(e) => match e.path().ok()?.to_str()?.starts_with(filter_prefix) {
                        true => Some(e),
                        false => None,
                    }
                }
            })
            .map(|mut entry| -> Result<PathBuf, String> {
                let entry_path = entry
                    .path()
                    .map_err(|e| e.to_string())?.to_path_buf();
                let p = if entry_path.starts_with(strip_prefix) {
                    entry_path.strip_prefix(strip_prefix)
                        .map_err(|e| format!("Failed to strip prefix from path '{:?}': {:?}", &entry_path, e.to_string()))?
                        .to_owned()
                } else {
                    entry_path
                };
                match entry.unpack(to_path.join(&p)) {
                    Ok(_) => {
                        if let Some(o) = owner {
                            match std::os::unix::fs::chown(to_path.join(&p), Some(o.0), Some(o.1)) {
                                Ok(()) => Ok(p),
                                Err(e) => Err(format!(
                                    "Failed to set ownership for {:?}: {}",
                                    p,
                                    e.to_string()
                                )),
                            }
                        } else {
                            Ok(p)
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            })
            .for_each(|x| match x {
                Ok(p) => {
                    write!(io_lock, "\r> {}", p.display().to_string()).unwrap();
                    io_lock.flush().unwrap();
                },
                Err(e) => {
                    writeln!(io_lock, "\n> ERR: {}", e).unwrap();
                },
            });
        writeln!(io_lock, "\r done.").unwrap();
        io_lock.flush().unwrap();
        Ok(Some(nc_temporary_backup_path.to_owned()))
    }
}

impl BackupProviderConfig for TarballBackupConfig {
    fn validate(&self) -> bool {
        return true;
    }

    fn get_restore_capabilities(&self, backup: &str) -> Result<RestoreCapabilities, String> {
        let backup_path = PathBuf::from(backup);

        let re_db = Regex::new(r"^nextcloud-sqlbkp_.*\.(bak|sql)$").map_err(|e| e.to_string())?;
        let re_files = Regex::new(r"^[^/]*/.ocdata$").map_err(|e| e.to_string())?;
        let re_nextcloud = Regex::new(r"^nextcloud/$").map_err(|e| e.to_string())?;

        if !backup_path.is_file() {
            return Err("Could not open backup: No such file".to_string());
        }
        let read = open_tarball(&backup_path)?;
        let mut archive = Archive::new(read);
        let mut caps = RestoreCapabilities {
            db: false,
            files: false,
            nextcloud: false,
            ncp_config: false,
        };
        for entry in archive
            .entries()
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
            })
            .filter_map(|e| e.ok())
        {
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
            return Err("No recoverable data found in backup".to_string());
        }
        Ok(caps)
    }

    fn get_ncp_system_config(&self, backup: &str) -> Option<NcpConfig> {
        todo!("Not implemented")
    }

    // fn get_ncp_system_config(&self, backup: &str) -> Option<NcpConfig> {
    //     let bkp_path = PathBuf::from(backup);
    //     let mut arch = match open_tarball(&bkp_path) {
    //         Ok(read) => Archive::new(read),
    //         Err(_) => return None,
    //     };
    //     let ncp_cfg_results = arch.entries().ok()?.filter_map(|e| match e {
    //         Ok(entry) => match &entry.path().ok()?.ends_with("ncp.cfg") {
    //             true => Some(entry),
    //             false => None
    //         }
    //         Err(_) => None
    //     }).map(|mut entry| -> Result<String, String> {
    //         let mut buffer = String::new();
    //         entry.read_to_string(&mut buffer).map_err(|_| "Failed to read ncp.cfg to string")?;
    //         return Ok(buffer);
    //     }).collect::<Result<Vec<String>, String>>().ok()?;
    //     if ncp_cfg_results.len() != 1 {
    //         return None
    //     }
    //     let ncp_cfg = ncp_cfg_results[0].to_string();
    //     todo!("Not yet implemented");
    // }

    // todo refactor to use some sort of restore process multistep engine
    fn restore(&self, backup_path: &str, restore_config: RestoreConfig) -> Result<(Option<PathBuf>, Option<PathBuf>), String> {
        let unpack_dir = restore_config
            .target_ncp_config
            .ncp_data_volume
            .parent()
            .unwrap_or(Path::new("/tmp"))
            .join(format!("/tmp/{}", Alphanumeric.sample_string(&mut rand::thread_rng(), 8)));
        let www_data_user =
            get_user_by_name("www-data").ok_or("Could not retrieve uid of user www-data")?;
        run_occ_command_blocking(
            &restore_config.target_ncp_config,
            vec!["maintenance:mode", "--on"],
        )?;

        let nc_bkp_path = if restore_config.restore_nextcloud {
            let redis_pw_re = Regex::new(r"(^|\n)\s*requirepass\s+(?P<pw>.*)\s*(\n|$)").unwrap();
            let redis_password = match fs::read_to_string(Path::new("/etc/redis/redis.conf")) {
                Ok(s) => {
                    match redis_pw_re.captures(&s) {
                        None => {
                            println!("Could not match redis pw line");
                            None
                        },
                        Some(caps) => match caps.name("pw") {
                            None => {
                                println!("Found redis password entry but couldn't extract pw");
                                None
                            },
                            Some(pw) => Some(pw.as_str().to_string()),
                        },
                    }
                }
                    .ok_or("Failed to find redis password".to_string()),
                Err(e) => Err(e.to_string()),
            }?;
            let mysql_password_re = Regex::new(r"(^|\n)\s*password=(?P<pw>.*)(\n|$)").unwrap();
            let mysql_password = match fs::read_to_string(Path::new("/root/.my.cnf")) {
                Ok(s) => match mysql_password_re.captures(&s) {
                    None => None,
                    Some(caps) => match caps.name("pw") {
                        None => None,
                        Some(pw) => Some(pw.as_str().to_string()),
                    },
                }
                    .ok_or("Failed to find mysql password".to_string()),
                Err(e) => Err(e.to_string()),
            }?;
            let bkp_path = self.restore_tarball_to(
                backup_path,
                &restore_config.target_ncp_config.nc_www_directory,
                "nextcloud/",
                "nextcloud/",
                Some((www_data_user.uid(), www_data_user.primary_group_id())),
            )?;
            set_nc_config_value(
                &restore_config.target_ncp_config,
                vec!["dbpassword"],
                &mysql_password,
                true,
            )?;
            set_nc_config_value(
                &restore_config.target_ncp_config,
                vec!["redis", "password"],
                &redis_password,
                true,
            )?;
            bkp_path
        } else {
            None
        };

        if restore_config.restore_db {
            self.restore_tarball_to(backup_path, &unpack_dir, "nextcloud-sqlbkp_", "", None)?;
            let sql_dump_path = unpack_dir
                .read_dir()
                .map_err(|e| e.to_string())?
                .find(|p| match p {
                    Err(_) => false,
                    Ok(e) => match e.file_name().to_str() {
                        None => false,
                        Some(s) => s.starts_with("nextcloud-sqlbkp_"),
                    },
                })
                .ok_or("Failed to extract db backup")?
                .map_err(|e| e.to_string())?
                .path();
            let mut sql_exec = "
                DROP DATABASE IF EXISTS nextcloud;
                CREATE DATABASE nextcloud;
                GRANT USAGE ON *.* TO '$DBADMIN'@'localhost' IDENTIFIED BY '$DBPASSWD';
                DROP USER '$DBADMIN'@'localhost';
                CREATE USER '$DBADMIN'@'localhost' IDENTIFIED BY '$DBPASSWD';
                GRANT ALL PRIVILEGES ON nextcloud.* TO $DBADMIN@localhost;
                EXIT";
            let mut mysql_proc = Command::new("mysql")
                .args(vec!["-u", "root"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?;
            mysql_proc
                .stdin
                .take()
                .unwrap()
                .write_all(sql_exec.as_bytes())
                .map_err(|e| e.to_string())?;
            let output = mysql_proc.wait_with_output().map_err(|e| e.to_string())?;
            if !output.status.success() {
                return Err(format!(
                    "Failed to restore db: \n  {}",
                    output
                        .stderr
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>()
                        .join("\n  ")
                ));
            }

            let mysql_proc = Command::new("mysql")
                .args(vec!["-u", "root", "nextcloud"])
                .stdin(Stdio::from(
                    File::open(sql_dump_path).map_err(|e| e.to_string())?,
                ))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?;
            let output = mysql_proc.wait_with_output().map_err(|e| e.to_string())?;
            if !output.status.success() {
                return Err(format!(
                    "Failed to restore db: \n  {}",
                    output
                        .stderr
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<String>>()
                        .join("\n  ")
                ));
            }
        }

        let ncp_data_bkp = if restore_config.restore_files {
            let ncp_data_volume_path = restore_config.target_ncp_config.ncp_data_volume.clone();
            let ncp_data_bkp = if ncp_data_volume_path.exists() {
                let bkp_file_name = match ncp_data_volume_path.file_name() {
                    None => None,
                    Some(s) => s.to_str(),
                }
                .ok_or("Failed to retrieve ncp data path -> Can't backup current data directory")?;
                let bkp_path =
                    ncp_data_volume_path.with_file_name(format!("{}_{}_bkp",
                                                                bkp_file_name,
                                                                Alphanumeric.sample_string(&mut rand::thread_rng(), 8)));
                let _ = fs::rename(ncp_data_volume_path, &bkp_path).map_err(|e| e.to_string())?;
                Some(bkp_path)
            } else {
                None
            };
            self.restore_tarball_to(
                backup_path,
                &restore_config.target_ncp_config.nc_data_directory,
                "data",
                "data",
                Some((www_data_user.uid(), www_data_user.primary_group_id())),
            )?;
            ncp_data_bkp
        } else {
            None
        };

        run_occ_command_blocking(
            &restore_config.target_ncp_config,
            vec!["maintenance:mode", "--off"],
        )?;
        if restore_config.restore_files {
            run_occ_command_blocking(
                &restore_config.target_ncp_config,
                vec!["files:scan", "--all"],
            )?;
        }

        if unpack_dir.exists() {
            if let Err(e) = fs::remove_dir_all(&unpack_dir) {
                println!("WANR: Failed to remove temporary directory {:?}: {:?}",
                unpack_dir, e);
            }
        }

        Ok((nc_bkp_path, ncp_data_bkp))
    }

    fn backup_info(&self, cache: &mut BackupCache, backup: &str, rescan: bool) -> Result<BackupInfo, String> {
        let index = Backup::Legacy(self.clone(), backup.to_string());
        if !cache.contains_key(&index) || rescan {
            let val = match self.get_restore_capabilities(backup) {
                Ok(r) => Some(r),
                Err(e) => {
                    println!("{:?}", e);
                    None
                }
            };
            cache.entry(index.clone()).insert_entry(val);
        }

        Ok(BackupInfo{
            capabilities: cache.get(&index).unwrap_or(&None).clone(),
            backup: index
        })
    }

    fn scan_backups(&self, cache: &mut BackupCache, rescan: bool) -> Result<(), String> {
        let files = fs::read_dir(&self.path).map_err(|e| e.to_string())?;
        for backup in files.flatten() {
            if let Some(bkp_str) = backup.path().to_str() {
                let index = Backup::Legacy(self.clone(), bkp_str.to_string());
                if cache.contains_key(&index) && !rescan {
                    continue;
                }
                let val = match self.get_restore_capabilities(bkp_str) {
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
        Ok(())
    }

    fn list_backups(&self, cache: &BackupCache) -> Vec<BackupInfo> {
        cache
            .keys()
            .map(|k| BackupInfo {
                backup: k.clone(),
                capabilities: cache.get(k).unwrap_or(&None).clone(),
            })
            .collect::<Vec<BackupInfo>>()
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

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    subcommand: BackupTypeCommand,
}

#[derive(Subcommand)]
enum BackupTypeCommand {
    Legacy {
        backups_path: String,
        #[command(subcommand)]
        command: TarballCommands
    }
}

#[derive(Subcommand)]
enum TarballCommands {
    List { },
    Info {
        backup: String
    },
    Restore {
        backup: String
    }
}

fn main() {
    // let args: Vec<String> = env::args().collect();
    assert!(geteuid().is_root(), "ERROR: Must be run as root (try sudo)");
    // println!("{:?}", NcpConfig::detect_system_config(false).unwrap());

    let cli = Cli::parse();

    let result = match &cli.subcommand {
        BackupTypeCommand::Legacy {command, backups_path} => {
            let mut backup_provider = BackupProvider::from_tarball_backup_directory(backups_path);
            match command {
                TarballCommands::List {} => {
                    match backup_provider.scan_backups(false) {
                        Err(e) => Err(e),
                        Ok(_) => {
                            println!(
                                "Tarball Backups:\n{}",
                                backup_provider
                                    .list_backups()
                                    .iter()
                                    .map(|b| format!("- {:?}", b))
                                    .collect::<Vec<String>>()
                                    .join("\n")
                            );
                            Ok(())
                        }
                    }
                },
                TarballCommands::Info {
                    backup
                } => {
                    match backup_provider.show_backup(backup, false) {
                        Err(e) => Err(e),
                        Ok(res) => {
                            println!("Tarball Backup: {:?}", res);
                            Ok(())
                        }
                    }
                },
                TarballCommands::Restore {
                    backup
                } => {
                    match backup_provider.get_restore_capabilities(backup) {
                        Err(e) => Err(e),
                        Ok(capa) => {
                            let config = RestoreConfig {
                                target_ncp_config: NcpConfig::detect_system_config(false).unwrap(),
                                source_ncp_config: None,
                                restore_files: capa.files,
                                restore_db: capa.db,
                                restore_nextcloud: capa.nextcloud,
                                restore_ncp_config: capa.ncp_config
                            };
                            match backup_provider.restore(backup, config) {
                                Err(e) => Err(e),
                                Ok((ncp_backup_path, nc_backup_path)) => {
                                    println!("Restore successful. {}{}",
                                        match ncp_backup_path {
                                            None => "".to_string(),
                                            Some(p) => format!("Old data directory was backed up to '{:?}'. ", p)
                                        },
                                        match nc_backup_path {
                                            None => "".to_string(),
                                            Some(p) => format!("Old nextcloud directory was backed up to '{:?}.", p)
                                        }
                                    );
                                    Ok(())
                                }
                            }
                        }
                    }

                }
            }
        },
    };

    if let Err(e) = result {
        println!("Error: {:?}", e)
    }
}
