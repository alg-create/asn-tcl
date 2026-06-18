# TCL-ASN

A pure Tcl 8.6 ASN.1 parser with a focused BER encoder/decoder.

The project parses ASN.1 module text into a Tcl dictionary AST and can encode or decode a practical subset of BER using that AST. It is not a full ASN.1/X.680 implementation yet; the current focus is a compact, well-tested core that can grow safely.

## Current Status

Supported parser features include:

- Module definitions with `EXPLICIT TAGS`, `IMPLICIT TAGS`, `AUTOMATIC TAGS`, and `EXTENSIBILITY IMPLIED`
- `EXPORTS` and `IMPORTS`
- Single-file parsing and multi-file parsing with import merging
- Type assignments and simple value assignments
- `INTEGER`, `BOOLEAN`, `ENUMERATED`, `OCTET STRING`, `BIT STRING`, `OBJECT IDENTIFIER`, `NULL`, `UTF8String`, `NumericString`, `PrintableString`, `IA5String`, `VisibleString`, and `ANY`
- `SEQUENCE`, `SET`, `CHOICE`
- `SEQUENCE OF` and `SET OF`
- Inline nested `SEQUENCE`, `SET`, and `CHOICE`, including inline element types for `SEQUENCE OF` / `SET OF`
- `COMPONENTS OF` inside `SEQUENCE` and `SET`
- Named numbers for `INTEGER`
- Named bits for `BIT STRING`
- Tags at type and component level
- `OPTIONAL`, `DEFAULT`, extension markers, extension addition groups, and extension additions storage
- Simple `RANGE` and `SIZE` constraints at type and component level
- Value assignments for simple literals, nested record-like values, binary and hex string literals, and `OBJECT IDENTIFIER` arcs with common names
- Parser-only recognition for `REAL`, `RELATIVE-OID`, `EXTERNAL`, `EMBEDDED PDV`, `UTCTime`, and `GeneralizedTime`
- AST invariant validation after parsing

Supported BER features include:

- Encode/decode for `INTEGER`, `BOOLEAN`, `ENUMERATED`, `OCTET STRING`, `BIT STRING`, `NULL`, `OBJECT IDENTIFIER`, `UTF8String`, `NumericString`, `PrintableString`, `IA5String`, `VisibleString`, and raw-TLV `ANY`
- Encode/decode for `SEQUENCE`, `SET`, `CHOICE`, `SEQUENCE OF`, `SET OF`
- Symbolic `ENUMERATED` values during encoding
- Automatic context tags for modules declared with `AUTOMATIC TAGS`
- Default-valued fields are omitted during encoding; `SEQUENCE` and `SET` decode use tags to skip absent `OPTIONAL`/`DEFAULT` fields and materialize defaults
- `SET` decode is order-independent for components with distinguishable BER tags
- Public low-level TLV helpers for tags, lengths, primitive TLVs, constructed TLVs, wrappers, and channel reads
- Explicit and implicit tags
- High tag numbers
- Definite length encoding
- Indefinite length decoding for supported constructed values
- Constraint enforcement for parsed `RANGE` and `SIZE` constraints

Notable limitations:

- DER canonical encoding is not implemented.
- Full X.682/X.683 constraint syntax is not implemented.
- BER for parser-only types such as `REAL`, `RELATIVE-OID`, `EXTERNAL`, `EMBEDDED PDV`, `UTCTime`, and `GeneralizedTime` is not implemented.
- Many string-family BER tags beyond the currently listed string types, object classes, parameterization, and information object sets are not implemented.
- Import merging only uses modules already parsed by `parse_str`, `parse_file`, or `parse_files`; it does not auto-discover files.

## Project Layout

```text
TCL-ASN/
|-- asn1_parser.tcl       # Core parser and BER logic
|-- pkgIndex.tcl          # Tcl package index
|-- README.md
|-- TESTING.md
|-- deps/
|   |-- muttcl/             # Vendored mutation testing framework
|-- tests/
|   |-- runtests.tcl
|   |-- mutation_runtests.tcl
|   |-- syntax.test
|   |-- modules.test
|   |-- ber.test
|   |-- ber_advanced.test
|   |-- ber_constraints.test
|   |-- new_types.test
|   |-- extensibility.test
|   |-- modules/
|   |   |-- *.asn
|-- tools/
|   |-- mutation_audit.tcl  # Progress-logging mutation audit wrapper
```

## API

Load the package:

```tcl
lappend auto_path /path/to/TCL-ASN
package require asn1
```

### `asn1::parse_str text`

Parses ASN.1 module text into an AST.

```tcl
set ast [asn1::parse_str {
    Demo DEFINITIONS ::= BEGIN
        Age ::= INTEGER (0..120)
    END
}]
```

### `asn1::parse_file filepath`

Reads and parses one ASN.1 file.

```tcl
set ast [asn1::parse_file tests/modules/01-simple.asn]
```

### `asn1::parse_files filepaths`

Reads several ASN.1 files as one compilation unit. This is the recommended API when modules import symbols from other files.

```tcl
set ast [asn1::parse_files [list \
    tests/modules/05-import-source-a.asn \
    tests/modules/06-import-source-b.asn \
    tests/modules/07-import-consumer.asn]]
```

### `asn1::ber_encode ast moduleName typeName value`

Encodes a Tcl value into BER bytes using a parsed type definition.

```tcl
set bytes [asn1::ber_encode $ast Demo Age 42]
puts [binary encode hex $bytes]
```

### `asn1::ber_decode ast moduleName typeName bytes`

Decodes BER bytes using a parsed type definition. Returns a dictionary with `value` and `remainder`.

```tcl
set decoded [asn1::ber_decode $ast Demo Age [binary decode hex 02012a]]
puts [dict get $decoded value]
```

### `asn1::ber_encode_value ast moduleName valueName`

Encodes a parsed ASN.1 value assignment.

## Low-Level BER/TLV Helpers

The package also exposes schema-independent BER helpers for socket protocols and custom framing code.

Tag and length helpers:

```tcl
asn1::ber_encode_tag $tagClass $constructedBit $tagNumber
asn1::ber_encode_length $length
asn1::ber_decode_tag $bytes idx class constructed number
asn1::ber_decode_length $bytes idx
```

`tagClass` uses BER class bits:

```tcl
0x00  ;# UNIVERSAL
0x40  ;# APPLICATION
0x80  ;# CONTEXT-SPECIFIC
0xC0  ;# PRIVATE
```

`constructedBit` is `0x00` or `0x20`.

Complete TLV helpers:

```tcl
asn1::ber_encode_tlv $tagClass $constructedBit $tagNumber $valueBytes
asn1::ber_decode_tlv $bytes ?startIndex?
```

`ber_decode_tlv` returns a dictionary containing:

```tcl
class constructed number length headerLength value tlv nextIndex
```

Convenience encoders:

```tcl
asn1::ber_encode_integer_tlv 42
asn1::ber_encode_boolean_tlv 1
asn1::ber_encode_utf8_string_tlv "hello"
asn1::ber_encode_null_tlv
asn1::ber_encode_sequence_tlv $contentBytes
asn1::ber_encode_set_tlv $contentBytes
```

Class wrappers:

```tcl
asn1::ber_wrap_context $tagNumber $valueBytes ?constructed?
asn1::ber_wrap_application $tagNumber $valueBytes ?constructed?
asn1::ber_wrap_private $tagNumber $valueBytes ?constructed?
```

Channel framing helpers:

```tcl
set tlv [asn1::ber_read_tlv $chan]
set seq [asn1::ber_read_sequence $chan]
```

`ber_read_tlv` reads exactly one definite-length top-level BER TLV from a binary Tcl channel. `ber_read_sequence` does the same and verifies that the top-level tag is a universal constructed `SEQUENCE`.

## AST Shape

Example schema:

```asn1
Demo DEFINITIONS IMPLICIT TAGS ::= BEGIN
    EXPORTS Person;

    Age ::= INTEGER (0..120)
    Algorithm ::= OBJECT IDENTIFIER

    Person ::= SEQUENCE {
        age [0] IMPLICIT INTEGER (0..120),
        name OCTET STRING (SIZE(1..50)),
        flags BIT STRING { active(0), admin(1) } OPTIONAL,
        scores SEQUENCE OF INTEGER (SIZE(1..3))
    }
END
```

Representative AST structure:

```tcl
Demo {
    tagging IMPLICIT
    imports {}
    exports {Person}
    types {
        Age {
            type INTEGER
            constraints {RANGE {0 120}}
        }
        Algorithm {
            type {OBJECT IDENTIFIER}
        }
        Person {
            type SEQUENCE
            components {
                age {
                    type INTEGER
                    constraints {RANGE {0 120}}
                    tag {class CONTEXT-SPECIFIC number 0 mode IMPLICIT}
                }
                name {
                    type {OCTET STRING}
                    constraints {SIZE {1 50}}
                }
                flags {
                    type {BIT STRING}
                    namedBits {active 0 admin 1}
                    optional true
                }
                scores {
                    type {SEQUENCE OF}
                    elementType INTEGER
                    constraints {SIZE {1 3}}
                }
            }
        }
    }
    values {}
}
```

## Imports

`IMPORTS` declarations are stored under each module's `imports` key. When source modules are present in the same parsed AST, imported value symbols and imported type dependency closures are merged into the importing module. Imported type definitions retain `originModule` metadata so nested references and default tag modes are resolved against the source module.

Unresolved import source modules, missing imported symbols, and missing helper types required by imported definitions are reported in the importing module's `errors_` list.

Use `parse_files` for cross-file imports:

```tcl
set ast [asn1::parse_files [list source-a.asn source-b.asn consumer.asn]]
```

`parse_file` intentionally parses only one file and does not search the filesystem for imported modules.

## Constraints

The parser currently stores simple constraints as:

```tcl
constraints {RANGE {0 120}}
constraints {RANGE 42}
constraints {SIZE {1 50}}
constraints {SIZE 4}
constraints {SIZE {4 | 8}}
```

BER encode/decode enforces these parsed `RANGE` and `SIZE` constraints for the supported types.

## Testing

Run all Tcl tests:

```powershell
tclsh tests\runtests.tcl
```

Python `asn1tools` can also be used as a BER oracle for selected cases. See [TESTING.md](TESTING.md) for setup and usage.

Mutation testing uses the vendored `muttcl` framework. For real audits, prefer
the project wrapper because it mutates a scratch copy and writes visible
progress to `.tmp`:

```powershell
tclsh tools\mutation_audit.tcl -progress-file .tmp\mutation_audit_full.log
```
