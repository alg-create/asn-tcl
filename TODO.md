# TODO

This file tracks ASN.1 features and cleanup work discussed but not yet implemented.

## Downstream SCAPI Priorities

Requested must-haves from downstream users, mapped to current project status:

### Must Have

- Channel framing helper indefinite-length support.
  - Current status: definite-length `ber_read_tlv` and `ber_read_sequence` are implemented.
  - Needed only if downstream sockets can send indefinite-length top-level messages.
  - Would require nested EOC scanning while reading from the channel.
- `AUTOMATIC TAGS` semantics.
  - Current status: parser assigns automatic context-specific component tags for untagged `SEQUENCE`, `SET`, and `CHOICE` components, including synthetic inline types.
  - Remaining: add SCAPI fixture coverage once real schemas are checked in.
- Inline anonymous type support.
  - Current status: component-level inline `SEQUENCE`, `SET`, and `CHOICE` are supported, including generalized inline element types for `SEQUENCE OF` / `SET OF` such as `SET OF CHOICE { ... }` and `SEQUENCE OF SEQUENCE { ... }`.
  - Remaining: add fixture coverage for more deeply nested SCAPI shapes.
- Cross-module imported type resolution.
  - Current status: imported type dependency closures are merged when modules are parsed together; imported types retain `originModule` metadata for nested BER resolution and source-module tagging defaults.
  - Needs validation with concrete SCAPI fixtures.
  - Add unresolved-import diagnostics.
- Symbolic `ENUMERATED` values.
  - Current status: parser stores named enumerants; BER encode accepts symbolic values such as `cardValidityCheck`.
  - Needed:
    - decode optionally returns symbolic values, or returns both symbolic and numeric
    - policy for extension enumerants
- More ASN.1 builtin/string types.
  - Current status: `UTF8String`, `PrintableString`, `NumericString`, and raw-TLV `ANY` BER support are implemented.
  - Needed soon:
    - `IA5String`
    - `VisibleString`
    - additional SCAPI string families as fixtures require them
- `DEFAULT` handling.
  - Current status: parser stores defaults; encode omits default-valued fields; `SEQUENCE` and `SET` decode use tags to skip absent `OPTIONAL`/`DEFAULT` fields and materialize defaults.
  - Needed:
    - clear API option for materialized vs omitted defaults if downstream needs it
- Clean unknown extension handling.
  - Current status: extensible `SEQUENCE` skips unknown trailing fields; `CHOICE` extension handling is limited.
  - Needed:
    - robust extension-addition skipping
    - better behavior for extensible `CHOICE`
    - tests with unknown extension data

### Nice To Have

- DER/canonical option.
  - See DER section below.
- Better diagnostics.
  - Parser errors should include module/type/field context and nearby token.
  - Unsupported constructs should fail clearly instead of causing malformed AST later.

## Parser Syntax

- Replace remaining ad hoc top-level type parsing branches with the shared `parse_type` path.
  - `SEQUENCE OF` and `SET OF` top-level assignments now use `parse_type`; structured `SEQUENCE`/`SET`/`CHOICE` and `ENUMERATED` still have explicit branches.
- Remove `parse_components_legacy` after the active parser path is fully cleaned up.
- Add `COMPONENTS OF` support for `SEQUENCE` and `SET`.
- Add extension addition group syntax:
  - `[[ ... ]]`
  - extension addition version markers
- Improve tokenizer coverage:
  - binary strings: `'0101'B`
  - hex strings: `'0A3F'H`
  - escaped/doubled quotes in character strings
  - better errors for unknown characters instead of silent skipping
- Add object identifier value syntax:
  - `{ iso member-body us ... }`
  - named arcs
  - mixed named/numeric arcs
- Add more built-in type syntax:
  - `REAL`
  - `RELATIVE-OID`
  - `EXTERNAL`
  - `EMBEDDED PDV`
  - time-related types if needed
- Add object class / information object syntax later:
  - `CLASS`
  - `WITH SYNTAX`
  - object assignments
  - object set assignments
- Add parameterized assignments later.
- Improve parser error reporting with token index and nearby token context.

## Constraints

- Replace flattened constraint dictionaries with a structured constraint AST.
- Support broader X.682 constraint syntax:
  - `MIN` / `MAX`
  - unions and intersections
  - exclusions
  - `FROM`
  - `WITH COMPONENT`
  - `WITH COMPONENTS`
  - `CONTAINING`
  - `PATTERN`
- Distinguish collection constraints from element constraints where ASN.1 grammar requires it.
- Add stricter parser validation for malformed constraint syntax.

## BER Encoder/Decoder

- Add proper BER tags and validation for ASN.1 string families:
  - `PrintableString`
  - `IA5String`
  - `VisibleString`
  - `BMPString`
  - `UniversalString`
  - `NumericString`
  - other useful character string types
- Add higher-level named-bit value helpers for `BIT STRING`.
- Add BER support for `REAL`.
- Add BER support for `RELATIVE-OID`.
- Add indefinite-length generation mode for constructed encodings.
- Improve diagnostics for ambiguous untagged `SET` components that share the same BER tag.
- Add stricter validation for trailing bytes inside `SEQUENCE`, `SET`, and `SEQUENCE OF` values.
- Add canonical boolean/integer validation on decode where appropriate.
- Expand constraint enforcement as the parser gains richer constraint ASTs.

## DER Support

- Add DER mode separate from BER mode.
- Enforce DER definite lengths only.
- Enforce minimal integer encodings.
- Enforce canonical boolean encoding.
- Sort `SET` and `SET OF` encodings as required by DER.
- Omit `DEFAULT` values during DER encoding.
- Reject BER forms that DER forbids.

## Imports / Modules

- Use `EXPORTS` during import resolution instead of only storing it.
- Decide behavior for modules without `EXPORTS`:
  - ASN.1 default export behavior
  - explicit empty export lists
- Report unresolved imports explicitly.
- Consider an optional resolver API for loading imported modules from directories.

## Testing

- Expand the Python `asn1tools` oracle harness beyond the current smoke cases.
- Add oracle checks for:
  - tags
  - `CHOICE`
  - `SET`
  - `OBJECT IDENTIFIER`
  - constraints
  - extension-related cases where supported
- Move the oracle script into a tracked test/helper location if it becomes a regular workflow.
- Add negative parser tests for malformed syntax and expected `errors_`/invariant failures.
- Add property-style round-trip tests for supported BER types.

## Documentation

- Keep `README.md` current as features land.
- Document AST schema more systematically.
- Document the supported ASN.1 subset versus unsupported standard features.
- Document BER value conventions for Tcl callers.
- Add examples for multi-file imports and constraint enforcement.
