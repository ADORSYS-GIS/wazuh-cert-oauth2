#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub use linux::restart_wazuh;

#[cfg(target_os = "macos")]
pub use macos::restart_wazuh;

#[cfg(target_os = "windows")]
pub use windows::restart_wazuh;
