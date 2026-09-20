//! Compiles the native nghttp3/ngtcp2 benchmark adapter through Cargo.

use std::{
    env,
    error::Error,
    fmt::Write,
    fs,
    path::{Path, PathBuf},
};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/native/client.c");
    println!("cargo:rerun-if-changed=src/native/server.c");
    println!("cargo:rerun-if-changed=src/native/nghttp3.c");
    println!("cargo:rerun-if-changed=src/native/native.h");
    println!("cargo:rerun-if-changed=src/headers.txt");

    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    if !matches!(target_os.as_str(), "windows" | "linux" | "macos") {
        return Err(format!(
            "the HTTP/3 Client benchmark supports Windows, Linux and macOS, not {target_os}"
        )
        .into());
    }
    let host = env::var("HOST")?;
    let target = env::var("TARGET")?;
    if host != target {
        return Err(format!(
            "the native benchmark Client must run on the build host; cross-compiling from {host} \
             to {target} is unsupported"
        )
        .into());
    }
    let target_env = env::var("CARGO_CFG_TARGET_ENV")?;
    if target_os == "windows" && target_env != "msvc" {
        return Err(format!(
            "the Windows HTTP/3 Client benchmark supports the MSVC toolchain, not {target_env}"
        )
        .into());
    }

    let output = required_path("OUT_DIR")?;
    generate_headers(&output)?;
    let mut build = cc::Build::new();
    build
        .file("src/native/client.c")
        .file("src/native/server.c")
        .file("src/native/nghttp3.c")
        .include(&output)
        .include(required_path("DEP_NGTCP2_INCLUDE")?)
        .include(required_path("DEP_NGHTTP3_INCLUDE")?)
        .include(required_path("DEP_AWS_LC_0_43_0_INCLUDE")?)
        .define("NGTCP2_STATICLIB", None)
        .define("NGHTTP3_STATICLIB", None)
        .opt_level(3)
        .warnings(true)
        .warnings_into_errors(true);

    if target_os == "windows" {
        build
            .define("WIN32_LEAN_AND_MEAN", None)
            .define("_WIN32_WINNT", Some("0x0A00"))
            .define("_CRT_SECURE_NO_WARNINGS", None)
            .flag_if_supported("/std:c11")
            .flag_if_supported("/utf-8")
            .flag("/external:anglebrackets")
            .flag_if_supported("/external:W0");
    } else {
        build
            .define("_POSIX_C_SOURCE", Some("200809L"))
            .flag_if_supported("-std=c11");
        if target_os == "linux" {
            build.define("_GNU_SOURCE", None);
        }
    }

    build.compile("http3_bench_nghttp3");

    if target_os == "windows" {
        for library in ["ws2_32", "bcrypt", "crypt32", "advapi32", "userenv"] {
            println!("cargo:rustc-link-lib={library}");
        }
    } else {
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=dl");
    }
    Ok(())
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    env::var_os(name)
        .map(PathBuf::from)
        .ok_or_else(|| format!("Cargo did not expose {name}").into())
}

fn generate_headers(output: &Path) -> Result<(), Box<dyn Error>> {
    let source = fs::read_to_string("src/headers.txt")?;
    let mut sections = [Vec::new(), Vec::new()];
    let mut seen = [false; 2];
    let mut section = None;
    for (line_number, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(index) = ["[request]", "[response]"]
            .iter()
            .position(|name| *name == line)
        {
            if seen[index] {
                return Err(format!(
                    "duplicate header fixture section at line {}",
                    line_number + 1
                )
                .into());
            }
            seen[index] = true;
            section = Some(index);
            continue;
        }
        let index = section.ok_or("header fixture field appears before its section")?;
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("malformed header fixture field at line {}", line_number + 1))?;
        let value = value.trim();
        // Printable ASCII has identical string-literal escaping in Rust and C.
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !value.bytes().all(|byte| (b' '..=b'~').contains(&byte))
            || sections[index]
                .iter()
                .any(|(existing, _)| *existing == name)
        {
            return Err(format!(
                "invalid or duplicate header fixture field at line {}",
                line_number + 1
            )
            .into());
        }
        sections[index].push((name, value));
    }
    let mut rust = String::new();
    let mut native = String::from(
        "typedef struct benchmark_header { const char *name; const char *value; } benchmark_header;\n",
    );
    for (name, fields) in ["REQUEST_HEADERS", "RESPONSE_HEADERS"].iter().zip(sections) {
        if fields.is_empty() || fields.len() >= 64 {
            return Err(format!("{name} must contain 1..63 fields").into());
        }
        writeln!(
            rust,
            "pub static {name}: [(http::HeaderName, http::HeaderValue); {}] = [",
            fields.len()
        )?;
        writeln!(native, "#define {name}_LEN {}", fields.len())?;
        // One translation unit defines the shared fixture; the others borrow it.
        writeln!(native, "#ifdef HTTP3_BENCH_DEFINE_HEADERS")?;
        writeln!(native, "const benchmark_header {name}[] = {{")?;
        for (field, value) in fields {
            writeln!(
                rust,
                "    (http::HeaderName::from_static({field:?}), http::HeaderValue::from_static({value:?})),"
            )?;
            writeln!(native, "  {{{field:?}, {value:?}}},")?;
        }
        rust.push_str("];\n");
        writeln!(native, "}};\n#else")?;
        writeln!(native, "extern const benchmark_header {name}[{name}_LEN];")?;
        native.push_str("#endif\n");
    }
    fs::write(output.join("headers.rs"), rust)?;
    fs::write(output.join("headers.h"), native)?;
    Ok(())
}
