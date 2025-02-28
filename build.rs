#[cfg(windows)]
fn find_npcap() {
    // Check environment variable first
    if let Ok(sdk_path) = std::env::var("NPCAP_SDK_DIR") {
        if let Some(path) = try_sdk_path(&sdk_path) {
            return;
        }
        eprintln!("Warning: NPCAP_SDK_DIR is set but SDK not found at {}", sdk_path);
    }

    // Try multiple possible Npcap SDK locations
    let possible_paths = [
        // 64-bit paths
        "C:/Program Files/Npcap/SDK/Lib/x64",
        "C:/Program Files/NPcapSDK/Lib/x64",
        "C:/Program Files (x86)/Npcap/SDK/Lib/x64",
        // 32-bit paths
        "C:/Program Files/Npcap/SDK/Lib",
        "C:/Program Files/NPcapSDK/Lib",
        "C:/Program Files (x86)/Npcap/SDK/Lib",
        // Additional common installation paths
        "C:/Npcap/SDK/Lib/x64",
        "C:/NPcapSDK/Lib/x64",
    ];

    // Check if any of the paths exist and use the first one found
    for path in possible_paths {
        if let Some(_) = try_sdk_path(path) {
            return;
        }
    }

    // If no paths were found, try using vcpkg
    if let Ok(_) = vcpkg::find_package("npcap") {
        return;
    }

    // If vcpkg fails, try using pkg-config as a last resort
    if let Ok(_) = pkg_config::probe_library("npcap") {
        return;
    }

    // If all methods fail, print a detailed error message
    eprintln!("\nError: Could not find Npcap SDK.");
    eprintln!("\nTried the following methods:");
    eprintln!("1. Environment variable NPCAP_SDK_DIR");
    eprintln!("2. Common installation paths:");
    for path in possible_paths {
        eprintln!("   - {}", path);
    }
    eprintln!("3. vcpkg package manager");
    eprintln!("4. pkg-config\n");
    eprintln!("To fix this, you can:");
    eprintln!("1. Install Npcap from https://npcap.com/ (select SDK option during installation)");
    eprintln!("2. Set NPCAP_SDK_DIR environment variable to your SDK location");
    eprintln!("3. Install npcap using vcpkg: vcpkg install npcap:x64-windows");
    eprintln!("4. Install the SDK manually to one of the above paths\n");
    std::process::exit(1);
}

#[cfg(windows)]
fn try_sdk_path(path: &str) -> Option<()> {
    if std::path::Path::new(path).exists() {
        println!("cargo:rustc-link-search={}", path);
        println!("cargo:rustc-link-lib=Packet");
        println!("cargo:rustc-link-lib=wpcap");
        Some(())
    } else {
        None
    }
}

#[cfg(unix)]
fn find_libpcap() {
    // On Unix systems, use pkg-config to find libpcap
    if pkg_config::probe_library("libpcap").is_err() {
        eprintln!("Error: Could not find libpcap.");
        eprintln!("Please install libpcap development files:");
        eprintln!("  Debian/Ubuntu: sudo apt-get install libpcap-dev");
        eprintln!("  Fedora: sudo dnf install libpcap-devel");
        eprintln!("  macOS: brew install libpcap");
        std::process::exit(1);
    }
}

fn main() {
    // Handle platform-specific dependencies
    #[cfg(windows)]
    find_npcap();

    #[cfg(unix)]
    find_libpcap();

    // Rebuild if build.rs changes
    println!("cargo:rerun-if-changed=build.rs");
} 