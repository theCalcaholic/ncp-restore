use std::{fmt, fs};
use std::fmt::Formatter;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use flate2::read::GzDecoder;
use rand::distributions::{Alphanumeric, DistString};
use regex::{Regex};
use tar::Archive;
use users::get_user_by_name;
use crate::{Backup, BackupCache, BackupConfig, BackupInfo, BackupProviderConfig, exec_mysql_statement, NcpConfig, RestoreCapabilities, RestoreConfig, set_db_permissions};
use crate::occ::{get_nc_config_value, run_occ_command_blocking, set_nc_config_value};

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct TarballBackupConfig {
    pub(crate) path: PathBuf,
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
        let nc_temporary_backup_path = to_path.with_file_name(format!(
            "{}_{}_bkp",
            match to_path.file_name() {
                Some(s) => s.to_str().unwrap_or("nextcloud"),
                None => "nextcloud",
            },
            Alphanumeric.sample_string(&mut rand::thread_rng(), 8)
        ));
        let old_data_existing = to_path.exists();
        if !old_data_existing {
            fs::create_dir_all(to_path).map_err(|e| e.to_string())?;
        }
        let mut io_lock = std::io::stderr().lock();
        let mut tarball = Archive::new(open_tarball(&PathBuf::from(tarball_path))?);
        writeln!(io_lock, "Calculating required disk space...").unwrap();
        let required_space = tarball
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
            .map(|entry| -> u64 {
                entry.size()
            }).reduce(|acc,s| s + acc)
            .unwrap_or(0);
        let fstat = rustix::fs::statvfs(to_path).unwrap();
        let available_space = fstat.f_bavail * fstat.f_bsize;
        if available_space < required_space + (100*1024*1024) {
            return Err(format!("Insufficient space for extracting backup at {:?}", to_path));
        }
        if old_data_existing {
            if let Err(e) = fs::rename(to_path, &nc_temporary_backup_path) {
                return Err(e.to_string());
            }
            fs::create_dir_all(to_path).map_err(|e| e.to_string())?;
        }
        writeln!(io_lock, "Done. Available space: {}, required space: {}, diff: {}", available_space, required_space, available_space - required_space).unwrap();
        writeln!(io_lock, "Extracting {:?} to {:?}...", &tarball_path, to_path).unwrap();
        let mut tarball = Archive::new(open_tarball(&PathBuf::from(tarball_path))?);
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
    pub fn get_restore_capabilities(backup: &str) -> Result<RestoreCapabilities, String> {
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
                    eprintln!("WARN: {:?}", s);
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

    pub fn backup_info(backup_config: Option<&TarballBackupConfig>, cache: Option<&mut BackupCache>, backup: &str, rescan: bool) -> Result<BackupInfo, String> {
        let index = Backup::Legacy(
            match backup_config {
                Some(cfg) => cfg.clone(),
                
                None => TarballBackupConfig{
                    path: PathBuf::from(backup).parent()
                        .ok_or(format!("could not get parent directory for \"{}\"", backup))?
                        .to_path_buf()
                }
            }, 
            backup.to_string()
        );
        let capas = match cache {
            Some(cache) => if ! cache.contains_key(&index) || rescan {
                let val = match TarballBackupConfig::get_restore_capabilities(backup) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        eprintln ! ("{:?}", e);
                        None
                    }
                };
                cache.entry(index.clone()).insert_entry(val.clone());
                val
            } else {
                cache.get(&index).unwrap_or(&None).clone()
            },
            None => match TarballBackupConfig::get_restore_capabilities(backup) {
                Ok(r) => Some(r),
                Err(e) => {
                    eprintln ! ("{:?}", e);
                    None
                }
            }
        };

        Ok(BackupInfo{
            capabilities: capas,
            backup: index
        })
    }
}

impl BackupProviderConfig for TarballBackupConfig {
    fn validate(&self) -> bool {
        return true;
    }

    fn get_restore_capabilities(&self, backup: &str) -> Result<RestoreCapabilities, String> {
        TarballBackupConfig::get_restore_capabilities(backup)
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

    fn create(&self, backup: &str, backup_config: BackupConfig, source_config: NcpConfig) -> Result<(), String> {
        todo!()
    }

    // todo refactor to use some sort of restore process multistep engine
    fn restore(&self, backup_path: &str, restore_config: RestoreConfig, target_config: NcpConfig) -> Result<(Option<PathBuf>, Option<PathBuf>), String> {
        let unpack_dir = &target_config
            .ncp_data_volume
            .parent()
            .unwrap_or(Path::new("/tmp"))
            .join(format!("/tmp/{}", Alphanumeric.sample_string(&mut rand::thread_rng(), 8)));
        let www_data_user =
            get_user_by_name("www-data").ok_or("Could not retrieve uid of user www-data")?;
        let mysql_password = Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
        run_occ_command_blocking(
            &target_config,
            vec!["maintenance:mode", "--on"],
        )?;

        let nc_bkp_path = if restore_config.restore_nextcloud {
            eprintln!("Restoring nextcloud directory ({:?})...", &target_config.nc_www_directory);
            let redis_pw_re = Regex::new(r"(^|\n)\s*requirepass\s+(?P<pw>.*)\s*(\n|$)").unwrap();
            let redis_password = match fs::read_to_string(Path::new("/etc/redis/redis.conf")) {
                Ok(s) => {
                    match redis_pw_re.captures(&s) {
                        None => {
                            eprintln!("Could not match redis pw line");
                            None
                        },
                        Some(caps) => match caps.name("pw") {
                            None => {
                                eprintln!("Found redis password entry but couldn't extract pw");
                                None
                            },
                            Some(pw) => Some(pw.as_str().to_string()),
                        },
                    }
                }
                    .ok_or("Failed to find redis password".to_string()),
                Err(e) => Err(e.to_string()),
            }?;
            let bkp_path = self.restore_tarball_to(
                backup_path,
                &target_config.nc_www_directory,
                "nextcloud/",
                "nextcloud/",
                Some((www_data_user.uid(), www_data_user.primary_group_id())),
            )?;
            // let mysql_password_re = Regex::new(r"(^|\n)\s*password=(?P<pw>.*)(\n|$)").unwrap();
            // let mysql_password = match fs::read_to_string(Path::new("/root/.my.cnf")) {
            //     Ok(s) => match mysql_password_re.captures(&s) {
            //         None => None,
            //         Some(caps) => match caps.name("pw") {
            //             None => None,
            //             Some(pw) => Some(pw.as_str().to_string()),
            //         },
            //     }
            //         .ok_or("Failed to find mysql password".to_string()),
            //     Err(e) => Err(e.to_string()),
            // }?;
            let dbname_re = Regex::new(r#"["']dbname["']\s*=>\s*["'](?P<dbname>[^"']*)["']"#).unwrap();
            let dbpass_re = Regex::new(r#"["']dbpassword["']\s*=>\s*["'](?P<pw>[^"']*)["']"#).unwrap();
            let (db_name, db_pass) = match fs::read_to_string(&target_config.nc_www_directory.join("config/config.php")) {
                Err(e) => return Err(e.to_string()),
                Ok(s) => (match dbname_re.captures(&s) {
                    None => None,
                    Some(caps) => match caps.name("dbname") {
                        None => None,
                        Some(dbname) => Some(dbname.as_str().to_string())
                    }
                }.ok_or("Failed to extract dbname from nextcloud/config/config.php".to_string())?,
                match dbpass_re.captures(&s) {
                    None => None,
                    Some(caps) => match caps.name("pw") {
                        None => None,
                        Some(pw) => Some(pw.as_str().to_string())
                    }
                }.ok_or("Failed to extract dbpassword from nextcloud/config/config.php".to_string())?)
            };
            set_db_permissions(&db_name, &db_pass, None)?;
            set_nc_config_value(
                &target_config,
                vec!["dbpassword"],
                &mysql_password,
                true,
            )?;
            set_db_permissions(&db_name, &mysql_password, None)?;
            set_nc_config_value(
                &target_config,
                vec!["redis", "password"],
                &redis_password,
                true,
            )?;
            let data_dir = &target_config.nc_data_directory;
            let data_dir_str = data_dir.to_str()
                .ok_or(format!("Failed to parse data directory {:?}", data_dir))?;
            set_nc_config_value(&target_config,
                                vec!["datadirectory"], data_dir_str, true)?;
            eprintln!("Success.");
            bkp_path
        } else {
            None
        };

        if restore_config.restore_db {
            eprintln!("Restoring database...");
            let db_name = get_nc_config_value(&target_config, vec!["dbname"], true)?;
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
            eprintln!("Deleting old DB...");
            let sql_exec = format!("
                DROP DATABASE IF EXISTS nextcloud;
                CREATE DATABASE {db_name};");
            match exec_mysql_statement(&sql_exec) {
                Err(e) => Err(format!("Failed to restore db: \n  {}", e)),
                Ok(()) => Ok(())
            }?;
            set_db_permissions(&db_name, &mysql_password, None)?;
            eprintln!("Importing DB backup...");
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
            eprintln!("Success.");
        }

        let ncp_data_bkp = if restore_config.restore_files {
            eprintln!("Restoring data directory ({:?})...", &target_config.nc_data_directory);
            let ncp_data_volume_path = target_config.ncp_data_volume.clone();
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
                &target_config.nc_data_directory,
                "data",
                "data",
                Some((www_data_user.uid(), www_data_user.primary_group_id())),
            )?;
            eprintln!("Success.");
            ncp_data_bkp
        } else {
            None
        };
        if restore_config.restore_files {
            eprintln!("Scanning files...");
            run_occ_command_blocking(
                &target_config,
                vec!["files:scan", "--all"],
            )?;
            eprintln!("done.")
        }

        run_occ_command_blocking(
            &target_config,
            vec!["maintenance:mode", "--off"],
        )?;

        if unpack_dir.exists() {
            eprintln!("Cleaning up temporary files...");
            if let Err(e) = fs::remove_dir_all(&unpack_dir) {
                eprintln!("WARN: Failed to remove temporary directory {:?}: {:?}",
                          unpack_dir, e);
            }
            eprintln!("done.")
        }

        eprintln!("Backup restored successfully.");

        Ok((nc_bkp_path, ncp_data_bkp))
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
                        eprintln!("{:?}", e);
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

    fn backup_info(&self, cache: &mut BackupCache, backup: &str, rescan: bool) -> Result<BackupInfo, String> {
        TarballBackupConfig::backup_info(Some(self), Some(cache), backup, rescan)
    }
}
