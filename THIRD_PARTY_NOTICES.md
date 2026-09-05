# Third-Party Notices

`libsshpp` links against and is a derivative work of the following third-party
software. This file is installed alongside the library per
[docs/design/01 §1.7](docs/design/01-goals-and-scope.md#17-licensing).

## libssh

* **Project**: https://www.libssh.org/
* **License**: LGPL-2.1-or-later
* **Usage**: `libsshpp` wraps libssh's C API; it is linked at build time (see
  [09 — Build and packaging](docs/design/09-build-and-packaging.md)) and is not
  vendored or redistributed with this repository.

## Catch2 (test-only, not distributed with the library)

* **Project**: https://github.com/catchorg/Catch2
* **License**: BSL-1.0 (Boost Software License 1.0)
* **Usage**: Used only to build and run `tests/`; not linked into `libsshpp`
  itself and not required to consume the library.

## OpenSSH (test fixture only, not distributed with the library)

* **Project**: https://www.openssh.com/
* **License**: BSD-style (see OpenSSH's own `LICENCE` file)
* **Usage**: `tests/integration/run_with_sshd.sh` spawns a real, ephemeral
  `sshd` as a test fixture; OpenSSH is not linked into or shipped with
  `libsshpp`.
