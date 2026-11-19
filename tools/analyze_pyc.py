#!/usr/bin/env python3

import argparse
import json
import types
from pathlib import Path

import xdis
from xdis.disasm import disassemble_file


def safe_value(value):
    if hasattr(value, "co_name"):
        return {
            "kind": "code",
            "name": value.co_name,
            "line": value.co_firstlineno,
        }
    if isinstance(value, bytes):
        return {
            "kind": "bytes",
            "length": len(value),
            "hex": value[:256].hex(),
        }
    if isinstance(value, (str, int, float, bool)) or value is None:
        return {"kind": type(value).__name__, "value": value}
    if isinstance(value, tuple):
        return {"kind": "tuple", "value": [safe_value(item) for item in value]}
    return {"kind": type(value).__name__, "repr": repr(value)}


def code_manifest(code):
    nested = []
    constants = []
    for item in code.co_consts:
        if hasattr(item, "co_name"):
            nested.append(code_manifest(item))
        else:
            constants.append(safe_value(item))

    positions = []
    co_lines = getattr(code, "co_lines", None)
    if co_lines is not None:
        try:
            positions = [
                {"start": start, "end": end, "line": line}
                for start, end, line in co_lines()
            ]
        except TypeError:
            positions = [
                {"start": start, "end": end, "line": line}
                for start, end, line in co_lines
            ]

    return {
        "name": code.co_name,
        "qualified_name": getattr(code, "co_qualname", code.co_name),
        "filename": code.co_filename,
        "first_line": code.co_firstlineno,
        "arg_count": code.co_argcount,
        "positional_only_arg_count": code.co_posonlyargcount,
        "keyword_only_arg_count": code.co_kwonlyargcount,
        "local_count": code.co_nlocals,
        "stack_size": code.co_stacksize,
        "flags": code.co_flags,
        "var_names": list(code.co_varnames),
        "names": list(code.co_names),
        "free_vars": list(code.co_freevars),
        "cell_vars": list(code.co_cellvars),
        "constants": constants,
        "line_positions": positions,
        "exception_table": repr(getattr(code, "co_exceptiontable", b"")),
        "nested": nested,
    }


def analyze_file(path, output_dir):
    loaded = xdis.load_module(str(path))
    version = loaded[0]
    code = loaded[3]

    output_dir.mkdir(parents=True, exist_ok=True)
    stem = path.stem

    disassembly = output_dir / f"{stem}.disassembly.txt"
    with disassembly.open("w", encoding="utf-8") as stream:
        disassemble_file(
            str(path),
            outstream=stream,
            asm_format="extended",
            show_source=False,
        )

    manifest = {
        "source": str(path),
        "python_version": ".".join(str(part) for part in version),
        "bytecode": code_manifest(code),
    }
    manifest_path = output_dir / f"{stem}.manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return disassembly, manifest_path


def main():
    parser = argparse.ArgumentParser(
        description="Analyze PyInstaller-extracted Python bytecode with xdis."
    )
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("analysis"))
    args = parser.parse_args()

    for path in args.paths:
        if path.is_dir():
            targets = sorted(path.rglob("*.pyc"))
        else:
            targets = [path]

        for target in targets:
            try:
                disassembly, manifest = analyze_file(target, args.output)
                print(f"{target}: {disassembly}")
                print(f"{target}: {manifest}")
            except Exception as exc:
                print(f"{target}: ERROR: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
