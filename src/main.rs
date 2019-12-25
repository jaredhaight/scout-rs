extern crate winapi;
extern crate winreg;
extern crate wmi;
extern crate proclist;
extern crate serde;

use std::env;
use std::collections::HashMap;
use serde::Deserialize;
use winapi::shared::minwindef::HKEY;
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;
use wmi::{COMLibrary, Variant, WMIConnection};

mod processes;

fn get_registry_value(hive: HKEY, key: &str, value: &str) -> String {
    let hive = RegKey::predef(hive);
    let registry_key_result = hive.open_subkey(key);
    let registry_key;

    match registry_key_result  {
        Ok(registry_key_result) => {
            registry_key = registry_key_result;
        },
        Err(_e) => {
            return "".to_string();
        }
    }

    let registry_value = registry_key.get_value(value);
    match registry_value {
        Ok(registry_value)=> {
           registry_value
        },
        Err(_e)=> {
           "".to_string()
        }
     }
}

fn main() {
    println!("\n\n================== SYSTEM INFO ==================");
    let username = env::var("USERNAME").unwrap_or_default();
    let domain_name = env::var("USERDOMAIN").unwrap_or_default();
    let computer_name = env::var("COMPUTERNAME").unwrap_or_default();
    let product_name = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductName");
    let edition_id = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "EditionID");
    let release_id = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ReleaseId");
    let build_branch = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "BuildBranch");
    let major_version = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "CurrentMajorVersionNumber");
    let current_version = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "CurrentVersion");
    
    println!("Username: {}", username);
    println!("Computer Name: {}", computer_name);
    println!("Domain: {}", domain_name);
    println!("Product Name: {}", product_name);
    println!("EditionID: {}", edition_id);
    println!("ReleaseID: {}", release_id);
    println!("Branch: {}", build_branch);
    println!("Major Version: {}", major_version);
    println!("Current Version: {}", current_version);

    println!("\n\n================== PROCESSES ==================");

    let process_infos = proclist::iterate_processes_info().filter_map(|r| r.ok());
    for process_info in process_infos {
        match processes::lists::defensive_processes().iter().find(|&process| process.name.to_lowercase() == process_info.name.to_lowercase()) {
            Some(inner) => println!("[Defensive Process] ({}) {} - {}", process_info.pid, process_info.name, inner.description),
            None => (),
        }
        match processes::lists::interesting_processes().iter().find(|&process| process.name.to_lowercase() == process_info.name.to_lowercase()) {
            Some(inner) => println!("[Interesting Process] ({}) {} - {}", process_info.pid, process_info.name, inner.description),
            None => (),
        }
        match processes::lists::browser_processes().iter().find(|&process| process.name.to_lowercase() == process_info.name.to_lowercase()) {
            Some(inner) => println!("[Browser Process] ({}) {} - {}", process_info.pid, process_info.name, inner.description),
            None => (),
        }
    }

    println!("\n\n================== SERVICES ==================");
    #[derive(Deserialize, Debug)]
    #[serde(rename = "Win32_Service")]
    #[serde(rename_all = "PascalCase")]
    struct ServiceDetail {
        display_name: String,
        path_name: String,
        state: String
    }

    let com_con = COMLibrary::new().unwrap();
    let wmi_con = WMIConnection::new(com_con.into()).unwrap();
    let results: Vec<ServiceDetail> = wmi_con.raw_query("SELECT * FROM Win32_Service").unwrap();
    
    for service in results {
        println!("Service: {}", service.display_name);
        println!("Path: {}", service.path_name);
        println!("Status: {}", service.state);
    }

    println!("\n\n================== POWERSHELL SETTINGS ==================");
    let powershell_2_version: String = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine", "PowerShellVersion");
    let powershell_3_version: String = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine", "PowerShellVersion");
    let transcription_value: String = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription", "EnableTranscripting");
    let transcription_folder: String = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription", "OutputDirectory");
    let module_logging_value: String = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging", "EnableModuleLogging");
    let module_logging_modules: String = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging", "ModuleNames");
    let script_block_logging_value: String = get_registry_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", "EnableScriptBlockLogging");


    println!("PowerShell 2 Version: {}", powershell_2_version);
    println!("PowerShell 5 Version: {}", powershell_3_version);
    println!("Module Logging: {}", module_logging_value);
    println!("Modules Logged: {}", module_logging_modules);
    println!("Script Block Logging: {}", script_block_logging_value);
    println!("Transaction Logging: {}", transcription_value);
    println!("Transaction Log Location: {}", transcription_folder);
    
    println!("\n\n===================== ANTIVIRUS (WMI) ====================");

    #[derive(Deserialize, Debug)]
    #[serde(rename = "AntiVirusProduct")]
    #[serde(rename_all = "PascalCase")]
    struct AVDetails {
        display_name: String,
        path_to_signed_product_exe: String,
        path_to_signed_reporting_exe: String,
    }

    let com_con = COMLibrary::new().unwrap();
    let wmi_con = WMIConnection::with_namespace_path("root\\SecurityCenter2", com_con.into()).unwrap();
    let results: Vec<AVDetails> = wmi_con.query().unwrap();

    for av in results {
        println!("Engine: {}", av.display_name);
        println!("Executable: {}", av.path_to_signed_product_exe);
        println!("Reporting Executable: {}", av.path_to_signed_reporting_exe);
    }

    println!("\n\n================== SYSMON CONFIG ===========================");
    let sysmon_hashing = get_registry_value(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters", "HashingAlgorithm");
    let sysmon_options = get_registry_value(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters", "HashingAlgorithm");
    // TODO: Implement Rules

    println!("Hashing: {}", sysmon_hashing);
    println!("Options: {}", sysmon_options);
}
