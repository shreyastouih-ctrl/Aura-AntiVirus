# Packaging

Build installers for each platform. All scripts read the version from
`crates/auraav-cli/Cargo.toml` and write into `dist/<os>/`. Each package ships
both the desktop GUI (`auraav-gui`) and the CLI (`auraav`).

| Platform | Command (host)               | Artifacts                                      |
| -------- | ---------------------------- | ---------------------------------------------- |
| Linux    | `packaging/linux/build.sh`   | `.tar.gz`, `.deb`, `.rpm`                       |
| Windows  | `packaging/windows/build.sh` | `.zip`, `.msi` (cross-built with mingw + wixl)  |

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

Packages install the GUI (`auraav-gui`), the CLI (`auraav`), a desktop entry
(`auraAV`) and an icon. The binaries locate their signatures/rules relative to
the executable (`<exe_dir>/data`, `<exe_dir>/../share/auraav/data`), so all
layouts above work.

## Windows

Cross-compiled from Linux (`rustup target add x86_64-pc-windows-gnu`,
`mingw-w64`, `wixl`). The `.msi` installs `auraav-gui.exe` + `auraav.exe` and
the data to `Program Files\auraAV`, and adds a **Start Menu shortcut** to the
GUI. The `.zip` is portable (double-click `auraav-gui.exe`).

## CI

`.github/workflows/release.yml` builds Linux and Windows and attaches the
artifacts to a GitHub Release when a `v*` tag is pushed (or via
`workflow_dispatch`).
