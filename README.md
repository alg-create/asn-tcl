# ASN.1 Module Parser for Tcl

A pure **Tcl 8.6** package designed to parse ASN.1 schema/specification files (`.asn`) into a structured Tcl dictionary representation (Abstract Syntax Tree / AST). It also includes a basic BER encoder and decoder to serialize and deserialize values against the parsed AST.

---

## Project Layout

The repository is structured logically to separate the core library logic from tests and sample schemas:

```text
TCL-ASN/
├── asn1_parser.tcl          # Core package file containing the parser and BER logic
├── README.md                # Project documentation (this file)
└── tests/                   # Test suite directory
    ├── runtests.tcl         # Test runner / harness
    ├── sanity_check.test    # Basic sanity test
    ├── file_parser.test     # Main parser test suite
    ├── modules.test         # Parser tests against the sample modules
    ├── ber.test             # BER encoder/decoder test suite
    └── modules/             # Directory containing sample ASN.1 schemas
```

---

## API Reference

To use the package in your Tcl script, require the `asn1` namespace:

```tcl
package require asn1
```

### `asn1::parse_file <filepath>`
Reads the ASN.1 schema file at the specified path, tokenizes its contents, and parses them into a nested Tcl dictionary representation.
* **Arguments:** `filepath` (string) — Absolute or relative path to the `.asn` file.
* **Returns:** A Tcl dictionary representing the parsed AST.

### `asn1::parse_str <text>`
Parses raw ASN.1 schema text into the AST dictionary.
* **Arguments:** `text` (string) — Raw ASN.1 specification text.
* **Returns:** A Tcl dictionary representing the parsed AST.

### `asn1::ber_encode <ast> <moduleName> <typeName> <value>`
Encodes a Tcl value into BER binary format based on the parsed AST definition.
* **Arguments:** 
  * `ast` (dict) — The parsed ASN.1 AST dictionary.
  * `moduleName` (string) — The name of the ASN.1 module containing the type.
  * `typeName` (string) — The name of the type to encode against.
  * `value` (any) — The Tcl value to encode.
* **Returns:** A binary string representing the BER encoding.

### `asn1::ber_decode <ast> <moduleName> <typeName> <bytes>`
Decodes a BER binary string into a Tcl value based on the parsed AST definition.
* **Arguments:**
  * `ast` (dict) — The parsed ASN.1 AST dictionary.
  * `moduleName` (string) — The name of the ASN.1 module containing the type.
  * `typeName` (string) — The name of the type to decode against.
  * `bytes` (binary string) — The BER binary data to decode.
* **Returns:** A dictionary containing `value` (the decoded Tcl value) and `remainder` (any unconsumed bytes).

---

## Abstract Syntax Tree (AST) Structure

When a module is successfully parsed, it returns a nested Tcl dictionary structure. Below is an example of the parsed AST structure:

### Example Schema
```asn
MyTestModule DEFINITIONS ::= BEGIN
    MyInteger ::= INTEGER
    
    MySequence ::= SEQUENCE {
        id INTEGER,
        name OCTET STRING,
        isActive BOOLEAN
    }
    
    MyChoice ::= CHOICE {
        opt1 MyInteger,
        opt2 BOOLEAN
    }
END
```

### Resulting AST Dictionary Representation
```tcl
MyTestModule {
    tagging EXPLICIT
    imports {}
    types {
        MyInteger {
            type INTEGER
        }
        MySequence {
            type SEQUENCE
            components {
                id {
                    type INTEGER
                }
                name {
                    type {OCTET STRING}
                }
                isActive {
                    type BOOLEAN
                }
            }
        }
        MyChoice {
            type CHOICE
            components {
                opt1 {
                    type MyInteger
                }
                opt2 {
                    type BOOLEAN
                }
            }
        }
    }
    values {}
}
```

---

### Constraints Representation

The parser also captures simple constraints (like `RANGE` and `SIZE`) placed on types.

```asn
ConstraintsModule DEFINITIONS ::= BEGIN
    Age ::= INTEGER (0..120)
    Name ::= PrintableString (SIZE(1..50))
END
```

```tcl
ConstraintsModule {
    tagging EXPLICIT
    imports {}
    types {
        Age {
            type INTEGER
            constraints {RANGE {0 120}}
        }
        Name {
            type PrintableString
            constraints {SIZE {1 50}}
        }
    }
    values {}
}
```

---

### Imports Representation (`IMPORTS`)

The parser supports parsing `IMPORTS` statements at the beginning of each module definition. The imported symbols are grouped by their source module and stored in the `imports` field at the root of the parsed module AST.

---

### Tagging Representation (IMPLICIT / EXPLICIT)

The parser supports tagging overrides at three levels:
1. **Module Level**: Default tagging (`EXPLICIT TAGS`, `IMPLICIT TAGS`, or `AUTOMATIC TAGS`) is stored in the `tagging` field at the root of each module.
2. **Type Level**: Individual type definitions can have tag descriptors (e.g. `GlobalTaggedType ::= [APPLICATION 2] IMPLICIT INTEGER`).
3. **Component Level**: Members inside `SEQUENCE` or `CHOICE` definitions can have tag descriptors.

When a tag is present on a type or component definition, a `tag` dictionary is added containing `class`, `number`, and `mode`.

---

## Testing

The project includes a comprehensive test suite based on `tcltest`.

### Running all tests:
From the root directory, execute `runtests.tcl` with Tcl:

```bash
tclsh tests/runtests.tcl
```

### Example output:
```text
Tests began at Tue Jun 02 15:00:00 CEST 2026
ber.test
file_parser.test
modules.test
sanity_check.test

Tests ended at Tue Jun 02 15:00:00 CEST 2026
runtests.tcl:	Total	12	Passed	12	Skipped	0	Failed	0
Sourced 4 Test Files.
```
