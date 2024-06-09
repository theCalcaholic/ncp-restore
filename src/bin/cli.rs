#![feature(setgroups)]
#![feature(entry_insert)]
extern crate core;

use rustix::process::geteuid;
use clap::{Parser, Subcommand};
use ncp_restore::{BackupProvider, NcpConfig, RestoreConfig};


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
    },
    Tar {
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

fn handle_tarball_commands(backups_path: &str, command: &TarballCommands) -> Result<(), String> {
    {
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
    }
}

fn main() {
    // let args: Vec<String> = env::args().collect();
    let cli = Cli::parse();
    assert!(geteuid().is_root(), "ERROR: Must be run as root (try sudo)");
    // println!("{:?}", NcpConfig::detect_system_config(false).unwrap());


    let result = match &cli.subcommand {
        BackupTypeCommand::Legacy {command, backups_path} => handle_tarball_commands(backups_path, command),
        BackupTypeCommand::Tar {command, backups_path} => handle_tarball_commands(backups_path, command)
    };

    if let Err(e) = result {
        eprintln!("Error: {:?}", e)
    }
}
