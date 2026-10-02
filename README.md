# PEHardeningReview

PEHardeningReview reads one local Portable Executable file and reports **declared** mitigation flags from its headers. It does not execute the file, load code, contact a network service, or modify the input. It uses only the Python standard library.

```sh
python -m pip install .
pe-hardening-review /path/to/your/file.exe
pe-hardening-review /path/to/your/file.exe --json
```

It reports DYNAMIC_BASE, NX_COMPAT, GUARD_CF and, for PE32+ images, HIGH_ENTROPY_VA. It also notes if the COFF header marks relocations stripped. These fields and offsets follow Microsoft's [PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). Missing flags become review notes, not vulnerability claims. The parser checks bounded DOS, PE, COFF, optional and section-table headers and rejects files over 64 MiB or direct symbolic links.

## Important limits

These bits are declarations. This tool does not validate a relocation directory, the CFG load configuration, a digital signature, the Windows loader, or whether any mitigation was enforced at runtime. It does not claim to identify malware or establish that a binary is safe. Only PE32 and PE32+ inputs within the stated size limit are supported.

## Verification

```sh
python -m unittest discover -s tests -v
python -m compileall -q src
```

Tests use synthetic PE32 and PE32+ inputs, including malformed offsets and truncation; see [VALIDATION.md](VALIDATION.md). This is a new implementation, separate from the attributed PEQuarry/pefile derivative. See [ORIGIN.md](ORIGIN.md). Use it on binaries you own or are authorized to inspect. Publication or passing tests do not establish CVP eligibility or approval; Anthropic's [CVP guidance](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude-opus-and-sonnet) requires a legitimate defensive use case affected by its safeguards.
