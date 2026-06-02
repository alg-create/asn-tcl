# TODO

This file tracks ASN.1 features and cleanup work discussed but not yet implemented.

## Parser Syntax

- Replace remaining ad hoc top-level type parsing branches with the shared `parse_type` path.
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
- Improve `SET` decode behavior so component order is not assumed.
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
