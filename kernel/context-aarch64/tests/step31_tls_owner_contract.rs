use kernal_context_aarch64::{Error, KernelThreadEntry, build_initial_context};

#[test]
fn hot_kernel_context_builder_has_no_tls_register_argument() {
    let _: fn(&mut [u64], u64, KernelThreadEntry, u64) -> Result<usize, Error> =
        build_initial_context;
}

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[test]
fn freestanding_tpidr_el0_owner_api_has_explicit_install_and_read_signatures() {
    let _: unsafe fn(u64) = kernal_context_aarch64::install_el0_thread_pointer;
    let _: unsafe fn() -> u64 = kernal_context_aarch64::read_el0_thread_pointer;
}
