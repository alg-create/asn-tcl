import os
import subprocess
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ORACLE_LIB = os.path.join(ROOT, ".tmp", "asn1tools_oracle")
sys.path.insert(0, ORACLE_LIB)

import asn1tools  # noqa: E402


SCHEMA = r"""
OracleModule DEFINITIONS ::= BEGIN
    Age ::= INTEGER (0..120)
    Flag ::= BOOLEAN
    Token ::= OCTET STRING (SIZE(4))
    Ids ::= SEQUENCE OF INTEGER (SIZE(1..3))
    Rec ::= SEQUENCE {
        age INTEGER (0..120),
        flag BOOLEAN,
        token OCTET STRING (SIZE(4)),
        ids SEQUENCE OF INTEGER (SIZE(1..3))
    }
END
"""


CASES = [
    ("Age", 42, "42", "42"),
    ("Flag", True, "1", "1"),
    ("Token", b"abcd", "abcd", "abcd"),
    ("Ids", [1, 2, 3], "{1 2 3}", "1 2 3"),
    (
        "Rec",
        {"age": 40, "flag": True, "token": b"abcd", "ids": [1, 2]},
        "[dict create age 40 flag 1 token abcd ids {1 2}]",
        "age 40 flag 1 token abcd ids {1 2}",
    ),
]


def tcl_encode(type_name, tcl_value):
    script = f"""
lappend auto_path {{{ROOT}}}
package require asn1
set schema {{{SCHEMA}}}
set ast [asn1::parse_str $schema]
puts [binary encode hex [asn1::ber_encode $ast OracleModule {type_name} {tcl_value}]]
"""
    proc = subprocess.run(
        ["tclsh"],
        input=script,
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    return proc.stdout.strip()


def tcl_decode(type_name, ber_hex):
    script = f"""
lappend auto_path {{{ROOT}}}
package require asn1
set schema {{{SCHEMA}}}
set ast [asn1::parse_str $schema]
set bytes [binary decode hex {ber_hex}]
puts [dict get [asn1::ber_decode $ast OracleModule {type_name} $bytes] value]
"""
    proc = subprocess.run(
        ["tclsh"],
        input=script,
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip())
    return proc.stdout.strip()


def main():
    compiled = asn1tools.compile_string(SCHEMA, "ber")
    failures = []

    for type_name, py_value, tcl_value, expected_tcl_decoded in CASES:
        oracle_hex = compiled.encode(type_name, py_value).hex()
        tcl_hex = tcl_encode(type_name, tcl_value)
        tcl_decoded = tcl_decode(type_name, oracle_hex)
        status = "OK" if oracle_hex == tcl_hex and tcl_decoded == expected_tcl_decoded else "MISMATCH"
        print(
            f"{status} {type_name}: "
            f"oracle={oracle_hex} tcl={tcl_hex} "
            f"tcl_decode={tcl_decoded!r}"
        )
        if oracle_hex != tcl_hex:
            failures.append(f"{type_name} encode")
        if tcl_decoded != expected_tcl_decoded:
            failures.append(f"{type_name} decode")

    if failures:
        print(f"Failed cases: {', '.join(failures)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
