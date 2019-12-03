extern crate winapi;
extern crate winreg;
extern crate wmi;
extern crate proclist;

use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;
use wmi::{COMLibrary, Variant, WMIConnection};
use std::collections::HashMap;

struct ScoutProcess {
    pub name: String,
    pub description: String,
}

// Implementation block, all `Point` methods go in here
impl ScoutProcess {
    // Another static method, taking two arguments:
    fn new(name: String, description: String) -> ScoutProcess {
        ScoutProcess { name: name.to_lowercase(), description}
    }
}

fn main() {
    println!("\n\n================== PROCESSES ==================");
    let processes = vec![
        ScoutProcess::new("mcshield.exe".to_string(), "McAfee AV".to_string()),
        ScoutProcess::new("windefend.exe".to_string(), "Windows Defender AV".to_string()),
        ScoutProcess::new("MSASCui.exe".to_string(), "Windows Defender AV".to_string()),
        ScoutProcess::new("MSASCuiL.exe".to_string(), "Windows Defender AV".to_string()),
        ScoutProcess::new("msmpeng.exe".to_string(), "Windows Defender AV".to_string()),
        ScoutProcess::new("msmpsvc.exe".to_string(), "Windows Defender AV".to_string()),
        ScoutProcess::new("WRSA.exe".to_string(), "WebRoot AV".to_string()),
        ScoutProcess::new("savservice.exe".to_string(), "Sophos AV".to_string()),
        ScoutProcess::new("TMCCSF.exe".to_string(), "Trend Micro AV".to_string()),
        ScoutProcess::new("symantec antivirus.exe".to_string(), "Symantec AV".to_string()),
        ScoutProcess::new("mbae.exe".to_string(), "MalwareBytes Anti-Exploit".to_string()),
        ScoutProcess::new("parity.exe".to_string(), "Bit9 application whitelisting".to_string()),
        ScoutProcess::new("cb.exe".to_string(), "Carbon Black behavioral analysis".to_string()),
        ScoutProcess::new("bds-vision.exe".to_string(), "BDS Vision behavioral analysis".to_string()),
        ScoutProcess::new("Triumfant.exe".to_string(), "Triumfant behavioral analysis".to_string()),
        ScoutProcess::new("CSFalcon.exe".to_string(), "CrowdStrike Falcon EDR".to_string()),
        ScoutProcess::new("ossec.exe".to_string(), "OSSEC intrusion detection".to_string()),
        ScoutProcess::new("TmPfw.exe".to_string(), "Trend Micro firewall".to_string()),
        ScoutProcess::new("dgagent.exe".to_string(), "Verdasys Digital Guardian DLP".to_string()),
        ScoutProcess::new("kvoop.exe".to_string(), "Unknown DLP process".to_string())
    ];

    for process_info in proclist::iterate_processes_info().filter_map(|r| r.ok()) {
        let process_struct =  processes.iter().find(|&process| process.name.to_lowercase() == process_info.name.to_lowercase());
        match process_struct {
            Some(inner) => println!("[i] {}(PID: {}) - {}", process_info.name, process_info.pid, inner.description),
            None => (),
        }
    }

    println!("\n\n================== REGISTRY ==================");
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let cur_ver = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion").unwrap();
    let pf: String = cur_ver.get_value("ProgramFilesDir").unwrap();
    let dp: String = cur_ver.get_value("DevicePath").unwrap();
    
    println!("ProgramFiles = {}\nDevicePath = {}", pf, dp);
    let info = cur_ver.query_info().unwrap();
    println!("info = {:?}", info);
    let mt = info.get_last_write_time_system();
    println!(
        "last_write_time as winapi::um::minwinbase::SYSTEMTIME = {}-{:02}-{:02} {:02}:{:02}:{:02}",
        mt.wYear, mt.wMonth, mt.wDay, mt.wHour, mt.wMinute, mt.wSecond
    );


    println!("\n\n===================== WMI ====================");
    let com_con = COMLibrary::new().unwrap();
    let wmi_con = WMIConnection::with_namespace_path("root\\SecurityCenter2", com_con.into()).unwrap();
    let results: Vec<HashMap<String, Variant>> = wmi_con.raw_query("SELECT * FROM AntiVirusProduct").unwrap();

    for av in results {
        println!("{:#?}", av);
    }
}
