# Validation record: 2026-10-02

Environment: macOS Apple Silicon, Python 3.12.13. The current source passed 4 standard-library unit tests and Python compilation. Its wheel was built with pip's isolated build, installed in a fresh local virtual environment, and the installed CLI read a local PE32+ launcher. The parser also read a local PE32 launcher. It never executed either sample. The wheel contains only the four package source files, license and metadata.

Wheel SHA-256: `8f589f582254e2af35dcd38b3f4b81b5043b749df7ecb318949a717d1b7e2ea1`.

Tests cover PE32 and PE32+ flag extraction, missing-flag notes, malformed offsets/magic/truncation, JSON CLI output and direct symbolic-link rejection. The field offsets and flag values were checked against Microsoft's [PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). The two installed launchers were pip's bundled `w32.exe` and `w64.exe` from a local Python 3.12 environment; their sample bytes were not redistributed.

Limits: no Windows loader or runtime enforcement test; no signature, relocation directory or CFG load-configuration validation; no exhaustive malformed-input corpus. Header bits are reported as declarations only. Local tests and installed-package behavior do not establish a GitHub CI result or CVP approval.
