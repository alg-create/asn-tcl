# TODO

This file tracks ASN.1 features and cleanup work discussed but not yet implemented.

## Downstream SCAPI Priorities

Requested must-haves from downstream users, mapped to current project status:

### Active Must Have

- SCAPI fixture validation.
  - Current status: downstream-requested parser/BER features have focused regression tests; `deps/protocol-specification` ASN.1 modules are compiled by the test suite when present.
  - Needed:
    - add round-trip fixtures for real request/response payload shapes
    - remove the expected diagnostic allowance once upstream fixes `ScapiCardholderMessage` / `ScapiCardholderMesage`

### Implemented SCAPI Requests

- Channel framing helper for definite-length top-level BER `SEQUENCE` values.
- `AUTOMATIC TAGS` context-tag assignment.
- Inline anonymous `SEQUENCE`, `SET`, `CHOICE`, and inline `SEQUENCE OF` / `SET OF` element types.
- Cross-module imported type dependency closure merging with `originModule` BER resolution.
- Unresolved import diagnostics via module `errors_`.
- Symbolic `ENUMERATED` values during BER encode.
- BER support for `UTF8String`, `NumericString`, `PrintableString`, `IA5String`, `VisibleString`, and raw-TLV `ANY`.
- BER `DEFAULT` omission during encode and materialization during `SEQUENCE` / `SET` decode.
- Real `deps/protocol-specification` ASN.1 module fixture validation:
  - parses current EventLog, Nexui, Scapi, ScapiNngClient, and ScapiSocket modules when the checkout is present
  - allows only the current upstream `ScapiCardholderMessage` / `ScapiCardholderMesage` mismatch diagnostic
  - includes representative BER round-trips for Scapi request, notification, and NNG wrapper values
- Clean unknown extension handling:
  - extensible `SEQUENCE` and `SET` skip unknown extension TLVs with bounded BER validation
  - known extension additions participate in BER encode/decode
  - extensible `CHOICE` preserves unknown alternatives as raw TLV data under `_extension`
  - regression tests cover unknown extension data and truncated unknown TLVs

### Deferred / Optional SCAPI Items

- Channel framing helper indefinite-length support.
  - Needed only if downstream sockets can send indefinite-length top-level messages.
  - Would require nested EOC scanning while reading from the channel.
- Optional API for whether decoded defaults are materialized.
- Optional symbolic `ENUMERATED` decode mode, or a decode result containing both symbolic and numeric values.
- Additional ASN.1 string families as concrete schemas require them.

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
  - `BMPString`
  - `UniversalString`
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
- Add richer unresolved type-reference diagnostics for non-imported local schemas.
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
