use std::process::{Command, Output};
use std::os::unix::process::CommandExt;
use rustix::path::Arg;
use users::get_user_by_name;
use crate::NcpConfig;

// TODO: Test
pub fn run_occ_command_blocking(ncp_config: &NcpConfig, args: Vec<&str>) -> Result<Output, String> {
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
    eprintln!(
        "running occ command: {} {}",
        &cmd1.get_program().as_str().unwrap(),
        &cmd1
            .get_args()
            .map(|s| s.to_str().unwrap())
            .collect::<Vec<&str>>()
            .join(" ")
    );
    cmd1.output().map_err(|e| e.to_string())
}

pub fn set_nc_config_value(
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

pub fn get_nc_config_value(
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
