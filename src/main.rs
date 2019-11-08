extern crate winapi;
extern crate winreg;
extern crate wmi;
extern crate proclist;

use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::RegKey;
use wmi::{COMLibrary, Variant, WMIConnection};
use std::collections::HashMap;

fn main() {
    println!("\n\n================== PROCESSES ==================");
    for process_info in proclist::iterate_processes_info().filter_map(|r| r.ok()) {
        println!("[name]: {}, [pid]: {}", process_info.name, process_info.pid);
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
