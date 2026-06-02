# TODO

This file tracks ASN.1 features and cleanup work discussed but not yet implemented.

## Downstream SCAPI Priorities

Requested must-haves from downstream users, mapped to current project status:

### Must Have

- Stable public low-level BER/TLV helper API.
  - Current status: partial/internal.
  - Existing helpers include `ber_encode_tag`, `ber_encode_length`, `ber_decode_tag`, `ber_decode_length`, integer helpers, and skip/extract helpers.
  - Needed:
    - public wrapper names and documented signatures
    - TLV read helper returning `{tag length value nextIndex}` or similar
    - public context/application/private wrapper helpers
    - tests for helper API stability
- Channel framing helper.
  - Needed: read one complete top-level BER TLV, usually a `SEQUENCE`, from a Tcl channel/socket and return complete TLV bytes.
  - Equivalent to legacy `asnGetResponse`.
  - Should handle short reads and long-form length.
  - Optional: validate expected top-level tag.
- `AUTOMATIC TAGS` semantics.
  - Current status: parser stores `AUTOMATIC`, but does not assign automatic context-specific component tags.
  - Needed for SCAPI request/response choices such as `registration`, `notification`, `interaction`.
- Inline anonymous type support.
  - Current status: component-level inline `SEQUENCE`, `SET`, and `CHOICE` are supported.
  - Missing:
    - `SET OF CHOICE { ... }`
    - `SEQUENCE OF SEQUENCE { ... }`
    - generalized inline element types for `SEQUENCE OF` / `SET OF`
- Cross-module imported type resolution.
  - Current status: imported symbols are merged when modules are parsed together.
  - Needs validation for nested/transitive imported type references in SCAPI fixtures.
  - Add unresolved-import diagnostics.
- Symbolic `ENUMERATED` values.
  - Current status: parser stores named enumerants, BER currently expects numeric values.
  - Needed:
    - encode using symbolic values like `cardValidityCheck`
    - decode optionally returns symbolic values, or returns both symbolic and numeric
    - policy for extension enumerants
- More ASN.1 builtin/string types.
  - Current status: `UTF8String` implemented; `PrintableString` and `NumericString` parse as simple type names but do not have BER support.
  - Needed soon:
    - `PrintableString`
    - `NumericString`
    - tolerate or implement `ANY`
- `DEFAULT` handling.
  - Current status: parser stores defaults; decode materializes defaults for missing fields in `SEQUENCE`/`SET`.
  - Needed:
    - encode should optionally omit default-valued fields
    - clear API option for materialized vs omitted defaults if downstream needs it
    - string default conversion tests, e.g. `language Iso639 DEFAULT "en"`
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
