extern crate winapi;
extern crate winreg;
extern crate wmi;
extern crate proclist;
extern crate serde;

use std::env;
use std::collections::HashMap;
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
    registry_key.get_value(value).unwrap_or_default()
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
        if let Some(inner) = processes::lists::defensive_processes().iter().find(|&process| process.name.to_lowercase() == process_info.name.to_lowercase()) { 
            println!("[Defensive Process] ({}) {} - {}", process_info.pid, process_info.name, inner.description) 
        }
        if let Some(inner) = processes::lists::interesting_processes().iter().find(|&process| process.name.to_lowercase() == process_info.name.to_lowercase()) {
            println!("[Interesting Process] ({}) {} - {}", process_info.pid, process_info.name, inner.description) 
        }
        if let Some(inner) = processes::lists::browser_processes().iter().find(|&process| process.name.to_lowercase() == process_info.name.to_lowercase()) {
            println!("[Browser Process] ({}) {} - {}", process_info.pid, process_info.name, inner.description) 
        }
    }

     println!("\n\n================== SERVICES ==================");
     let com_con = COMLibrary::without_security().unwrap();
     let wmi_con = WMIConnection::new(com_con.into()).unwrap();
     let query_result = wmi_con.raw_query("SELECT * FROM Win32_Service");
     let results: Vec<HashMap<String, Variant>> = query_result.unwrap();

    for result in results {
        if let Some(wmi::Variant::String(value)) = result.get("DisplayName") {
            println!("Service: {}", value)
        }
        if let Some(wmi::Variant::String(value)) = result.get("PathName") {
            println!("Path: {}", value)
        }
        if let Some(wmi::Variant::String(value)) = result.get("State") {
            println!("State: {}\n", value)
        }
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

    let av_com_con = COMLibrary::without_security().unwrap();
    let av_wmi_con = WMIConnection::with_namespace_path("root\\SecurityCenter2", av_com_con.into()).unwrap();
    let results: Vec<HashMap<String, Variant>> = av_wmi_con.raw_query("SELECT * FROM AntiVirusProduct").unwrap();

    for result in results {
        if let Some(wmi::Variant::String(value)) = result.get("displayName") {
            println!("Engine: {}", value)
        }
        if let Some(wmi::Variant::String(value)) = result.get("pathToSignedProductExe") {
            println!("Executable: {}", value)
        }
        if let Some(wmi::Variant::String(value)) = result.get("pathToSignedReportingExe") {
            println!("Reporting Executable: {}", value)
        }
    }

    println!("\n\n================== SYSMON CONFIG ===========================");
    let sysmon_hashing = get_registry_value(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters", "HashingAlgorithm");
    let sysmon_options = get_registry_value(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters", "HashingAlgorithm");
    // TODO: Implement Rules

    println!("Hashing: {}", sysmon_hashing);
    println!("Options: {}", sysmon_options);
}
