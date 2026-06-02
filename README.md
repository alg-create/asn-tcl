# ASN.1 Module Parser for Tcl

A pure **Tcl 8.6** package designed to parse ASN.1 schema/specification files (`.asn`) into a structured Tcl dictionary representation (Abstract Syntax Tree / AST). 

This package is dedicated solely to schema parsing and AST generation. It does not perform binary encoding/decoding (e.g., BER, DER), making it a lightweight tool for analyzing or compiling ASN.1 specifications directly in Tcl environments.

---

## Project Layout

The repository is structured logically to separate the core library logic from tests and sample schemas:

```text
TCL-ASN/
├── asn1_parser.tcl          # Core package file containing the parser logic
├── README.md                # Project documentation (this file)
└── tests/                   # Test suite directory
    ├── run_all.tcl          # Test runner / harness
    ├── asn1_parser_test.tcl # Main parser test suite
    ├── test_schema.asn      # Sample ASN.1 schema for testing basic types, SEQUENCE, and CHOICE
    └── constraints_schema.asn # Sample ASN.1 schema for constraint definitions
```

---

## API Reference

To use the parser in your Tcl script, package-require the `asn1` namespace:

```tcl
package require asn1 1.0
```

### `asn1::parse_file <filepath>`
Reads the ASN.1 schema file at the specified path, tokenizes its contents, and parses them into a nested Tcl dictionary representation.
* **Arguments:** `filepath` (string) — Absolute or relative path to the `.asn` file.
* **Returns:** A Tcl dictionary representing the parsed AST.

### `asn1::parse <tokens>`
Parses a list of token strings into the AST dictionary. Useful if you have a pre-tokenized list of strings.
* **Arguments:** `tokens` (list) — A Tcl list of tokens.
* **Returns:** A Tcl dictionary representing the parsed AST.

### `asn1::tokenize <text>`
Extracts tokens from raw ASN.1 schema text, filtering out block comments (`/* ... */`), line comments (`-- ...`), and whitespace.
* **Arguments:** `text` (string) — Raw ASN.1 specification text.
* **Returns:** A Tcl list of tokens.

---

## Abstract Syntax Tree (AST) Structure

When a module is successfully parsed, it returns a nested Tcl dictionary structure. Below is an example of the parsed AST structure for `tests/test_schema.asn`:

### Example Schema (`test_schema.asn`)
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

### Tagging Representation (IMPLICIT / EXPLICIT)

The parser supports tagging overrides at three levels:
1. **Module Level**: Default tagging (`EXPLICIT TAGS`, `IMPLICIT TAGS`, or `AUTOMATIC TAGS`) is stored in the `tagging` field at the root of each module (defaulting to `EXPLICIT` if not specified).
2. **Type Level**: Individual type definitions can have tag descriptors (e.g. `GlobalTaggedType ::= [APPLICATION 2] IMPLICIT INTEGER`).
3. **Component Level**: Members inside `SEQUENCE` or `CHOICE` definitions can have tag descriptors (e.g. `customMember [PRIVATE 14] IMPLICIT MyIdentifier`).

When a tag is present on a type or component definition, a `tag` dictionary is added containing:
- `class`: `UNIVERSAL`, `APPLICATION`, `PRIVATE`, or `CONTEXT-SPECIFIC` (the default if omitted).
- `number`: The tag integer value.
- `mode`: `IMPLICIT` or `EXPLICIT` (only included if explicitly declared in the schema).

#### Example Tagged Schema
```asn
MyTaggedModule DEFINITIONS IMPLICIT TAGS ::= BEGIN
    GlobalTaggedType ::= [APPLICATION 2] IMPLICIT INTEGER
    
    TaggedSequence ::= SEQUENCE {
        standardMember BOOLEAN,
        customMember   [PRIVATE 14] IMPLICIT MyIdentifier
    }
END
```

#### Parsed AST Representation
```tcl
MyTaggedModule {
    tagging IMPLICIT
    types {
        GlobalTaggedType {
            type INTEGER
            tag {
                class APPLICATION
                number 2
                mode IMPLICIT
            }
        }
        TaggedSequence {
            type SEQUENCE
            components {
                standardMember {
                    type BOOLEAN
                }
                customMember {
                    type MyIdentifier
                    tag {
                        class PRIVATE
                        number 14
                        mode IMPLICIT
                    }
                }
            }
        }
    }
    values {}
}
```

---

## Testing

The project includes a comprehensive test suite. You can run individual tests or run the full test suite using the included test harness.

### Running all tests:
Navigate to the `tests/` directory and execute `run_all.tcl` with Tcl:

```bash
cd tests
tclsh run_all.tcl
```

### Example output:
```text
========================================
  ASN.1 Parser Test Harness 
========================================
Running: asn1_parser_test.tcl
[PASS] asn1_parser_test.tcl
----------------------------------------
Summary: 1 tests run, 1 passed, 0 failed.
```
