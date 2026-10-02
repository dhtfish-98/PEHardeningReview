"""Bounded PE header parser; it never loads or executes an input image."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import struct
from .local_input import read_local_file

MAX_FILE_BYTES = 64 * 1024 * 1024
IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000


class PEFormatError(ValueError):
    """The input does not contain a supported, bounded PE header."""


@dataclass(frozen=True)
class Report:
    format: str
    machine: str
    section_count: int
    relocations_stripped: bool
    dynamic_base_declared: bool
    nx_compatible_declared: bool
    guard_cf_declared: bool
    high_entropy_va_declared: bool | None
    review_notes: tuple[str, ...]

    def export(self) -> dict[str, str | int | bool | None | list[str]]:
        output = asdict(self)
        output["review_notes"] = list(self.review_notes)
        return output


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise PEFormatError("truncated PE header")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise PEFormatError("truncated PE header")
    return struct.unpack_from("<I", data, offset)[0]


def inspect_bytes(data: bytes) -> Report:
    """Read declared flags from bounded headers, without inferring OS enforcement."""
    if len(data) > MAX_FILE_BYTES:
        raise PEFormatError("input exceeds 64 MiB limit")
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEFormatError("missing or truncated DOS header")
    pe_offset = _u32(data, 0x3C)
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise PEFormatError("PE header offset is outside the file")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise PEFormatError("missing PE signature")

    coff = pe_offset + 4
    machine = _u16(data, coff)
    sections = _u16(data, coff + 2)
    optional_size = _u16(data, coff + 16)
    characteristics = _u16(data, coff + 18)
    optional = coff + 20
    if not 1 <= sections <= 96:
        raise PEFormatError("unsupported section count")
    if optional_size < 72 or optional + optional_size > len(data):
        raise PEFormatError("optional header is truncated")
    magic = _u16(data, optional)
    if magic not in (0x10B, 0x20B):
        raise PEFormatError("unsupported optional header magic")
    if optional_size < (112 if magic == 0x20B else 96):
        raise PEFormatError("optional header lacks required Windows fields")
    if optional + optional_size + sections * 40 > len(data):
        raise PEFormatError("section table is truncated")

    flags = _u16(data, optional + 70)
    reloc_stripped = bool(characteristics & IMAGE_FILE_RELOCS_STRIPPED)
    dynamic_base = bool(flags & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    nx_compatible = bool(flags & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    guard_cf = bool(flags & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
    high_entropy = bool(flags & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) if magic == 0x20B else None
    notes: list[str] = []
    if not dynamic_base:
        notes.append("DYNAMIC_BASE is not declared; review ASLR requirements")
    if reloc_stripped:
        notes.append("Relocations are marked stripped; review whether relocation is possible")
    if not nx_compatible:
        notes.append("NX_COMPAT is not declared; review DEP requirements")
    if not guard_cf:
        notes.append("GUARD_CF is not declared; review CFG requirements")
    if magic == 0x20B and not high_entropy:
        notes.append("HIGH_ENTROPY_VA is not declared for this PE32+ image")

    return Report(
        format="PE32+" if magic == 0x20B else "PE32",
        machine=f"0x{machine:04x}",
        section_count=sections,
        relocations_stripped=reloc_stripped,
        dynamic_base_declared=dynamic_base,
        nx_compatible_declared=nx_compatible,
        guard_cf_declared=guard_cf,
        high_entropy_va_declared=high_entropy,
        review_notes=tuple(notes),
    )


def inspect_file(path: str | Path) -> Report:
    source = Path(path).expanduser()
    if source.is_symlink() or not source.is_file():
        raise PEFormatError("input must be a regular local file, not a symbolic link")
    try:
        data = read_local_file(source, MAX_FILE_BYTES)
    except ValueError as exc:
        raise PEFormatError(str(exc)) from exc
    except OSError as exc:
        raise PEFormatError(f"cannot read input: {exc.strerror or type(exc).__name__}") from exc
    return inspect_bytes(data)
