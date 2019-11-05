extern crate sysinfo;
extern crate winreg;
extern crate wmi;

use std::collections::HashMap;

use sysinfo::{SystemExt, System, ProcessExt};
use winreg::enums::*;
use winreg::RegKey;
use wmi::{COMLibrary, WMIConnection, Variant};

fn main() {

    let mut sys = System::new();

    sys.refresh_all();

    println!("\n\n================= PROCESSES =================");
    for (pid, proc_) in sys.get_process_list() {
        println!("{}:{} => status: {:?}", pid, proc_.name(), proc_.status());
    }

    println!("\n\n=================== MEMORY ===================");
    println!("Total Memory: {} kB", sys.get_total_memory());
    println!("Used Memory: {} kB", sys.get_used_memory());


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
