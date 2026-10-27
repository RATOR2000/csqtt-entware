// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Entware glibc 2.27 was built against old kernel headers. Its exported
// getrandom wrapper may be an ENOSYS stub even on the target's Linux 4.9.
// Preserve the OS CSPRNG and syscall semantics instead of weakening randomness.
#[cfg(all(target_os = "linux", target_arch = "mips", target_env = "gnu"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrandom(
    buffer: *mut libc::c_void,
    length: libc::size_t,
    flags: libc::c_uint,
) -> libc::ssize_t {
    unsafe { libc::syscall(libc::SYS_getrandom, buffer, length, flags) as libc::ssize_t }
}

#[cfg(test)]
mod tests {
    #[test]
    fn operating_system_entropy_and_uuid_are_available() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        assert!(getrandom::fill(&mut first).is_ok());
        assert!(getrandom::fill(&mut second).is_ok());
        assert!(first.iter().any(|byte| *byte != 0));
        assert!(first != second);
        let id = uuid::Uuid::new_v4();
        assert_eq!(id.get_version_num(), 4);
    }
}
