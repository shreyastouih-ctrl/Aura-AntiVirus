# Packaging

Build installers for each platform. All scripts read the version from
`crates/auraav-cli/Cargo.toml` and write into `dist/<os>/`.

| Platform | Command (host)            | Artifacts                                   |
| -------- | ------------------------- | ------------------------------------------- |
| Linux    | `packaging/linux/build.sh`   | `.tar.gz`, `.deb`, `.rpm`                 |
| Windows  | `packaging/windows/build.sh` | `.zip`, `.msi` (cross-built with mingw+wixl) |
| macOS    | `packaging/macos/build.sh`   | `.pkg`, `.dmg` (macOS host only)          |

## Linux

```sh
packaging/linux/build.sh
# portable install (any prefix):
tar -xzf dist/linux/auraav-*-linux-amd64.tar.gz
sudo ./auraav-*-linux-x86_64/install.sh --prefix /usr/local
# or package managers:
sudo dpkg -i dist/linux/auraav_*_amd64.deb
sudo rpm  -i dist/linux/auraav-*.rpm
```

The binary locates its signatures/rules relative to the executable
(`<exe_dir>/data`, `<exe_dir>/../share/auraav/data`), so all layouts above work.

## Windows

Cross-compiled from Linux (`rustup target add x86_64-pc-windows-gnu`,
`mingw-w64-gcc`, `wixl`). The `.msi` installs to `Program Files\auraAV`,
adds the directory to `PATH`, and places data in `Program Files\auraAV\data`.

## macOS

Requires a macOS host (Apple `pkgbuild`/`hdiutil`). Not buildable on Linux;
use the CI workflow, which runs it on a `macos-latest` runner.

## CI

`.github/workflows/release.yml` builds all three platforms and attaches the
artifacts to a GitHub Release when a `v*` tag is pushed (or run manually via
workflow_dispatch).
