// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Native OpenWrt adapter. Routing and firewall policy belong to netifd/fw4.

use anyhow::{Context, Result, bail};
use std::{fs::File, net::Ipv4Addr};

pub const MTU: u16 = 1300;

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() >= 16 || name.starts_with('-')
        || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
        bail!("invalid TUN interface name");
    }
    Ok(())
}

/// The returned descriptor owns a nonpersistent interface: closing the final
/// descriptor removes it, including its connected routes, after a crash.
#[cfg(target_os = "linux")]
pub fn open(name: &str) -> Result<File> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    validate_name(name)?;
    let file = std::fs::OpenOptions::new().read(true).write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/net/tun").context("open /dev/net/tun (install kmod-tun)")?;
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_TUN_EXCL) as libc::c_short;
    // libc declares the request as c_ulong on glibc and c_int on musl.
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF as _, &request) } < 0 {
        return Err(std::io::Error::last_os_error()).context("create exclusive TUN interface");
    }
    Ok(file)
}

#[cfg(not(target_os = "linux"))]
pub fn open(_name: &str) -> Result<File> { bail!("native TUN requires Linux") }

pub async fn configure(name: &str, ip: Ipv4Addr) -> Result<()> {
    validate_name(name)?;
    for args in [
        vec!["address".to_owned(), "replace".to_owned(), format!("{ip}/32"), "dev".to_owned(), name.to_owned()],
        vec!["link".to_owned(), "set".to_owned(), "dev".to_owned(), name.to_owned(), "mtu".to_owned(), MTU.to_string(), "up".to_owned()],
    ] {
        let status = tokio::time::timeout(std::time::Duration::from_secs(10),
            tokio::process::Command::new("/sbin/ip").args(args)
                .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null()).kill_on_drop(true).status()).await??;
        if !status.success() { bail!("configure TUN interface failed"); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interface_names_cannot_be_options_or_paths() {
        assert!(validate_name("csqtt0").is_ok());
        for name in ["", "-tun", "../tun", "tun x", "tun;reboot", "1234567890123456"] {
            assert!(validate_name(name).is_err());
        }
    }
}
