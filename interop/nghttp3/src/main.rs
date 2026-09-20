//! Local native server entry, adapted from the fixed http3 benchmark wrapper.
use std::ffi::{c_char, c_int, CString};
unsafe extern "C" {
    fn http3_bench_nghttp3_server_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args()
        .map(CString::new)
        .collect::<Result<Vec<_>, _>>()?;
    let argc = c_int::try_from(args.len())?;
    let mut argv = args
        .iter()
        .map(|a| a.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null_mut());
    // SAFETY: version queries have no pointer inputs and return static data.
    // Referencing each crate retains its native linker contract.
    unsafe {
        let _ = aws_lc_sys::OpenSSL_version(0);
        let _ = ngtcp2_sys::ngtcp2_version(0);
        let _ = nghttp3_sys::nghttp3_version(0);
    }
    // SAFETY: this process calls the synchronous C entry exactly once. It only
    // reads argv and retains no pointers. All CStrings and the trailing-null
    // vector outlive the call; no threads access the native process state.
    let code = unsafe { http3_bench_nghttp3_server_main(argc, argv.as_mut_ptr()) };
    std::process::exit(code);
}
