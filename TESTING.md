# Testing

## Tcl Test Suite

Run the full Tcl test suite from the repository root:

```powershell
tclsh tests\runtests.tcl
```

Focused test files can be run directly:

```powershell
tclsh tests\syntax.test
tclsh tests\ber.test
tclsh tests\ber_constraints.test
tclsh tests\modules.test
```

The full suite also loads `tclmut` from `deps\muttcl\lib` and parses the
project Tcl sources/tests via `tests\muttcl_integration.test`. That integration
test also runs TclMut's in-place runner against a disposable fixture to verify
the project uses the framework API with a list-form test command and restores
mutated targets.

## Mutation Testing

The vendored mutation framework lives in `deps\muttcl`. To list mutation
candidates for the core parser:

```powershell
tclsh deps\muttcl\tclmut.tcl mutants asn1_parser.tcl
```

To run a full mutation pass, start from a clean worktree because TclMut mutates
the target file in place and restores it after each candidate:

```powershell
git status --short
tclsh deps\muttcl\tclmut.tcl run asn1_parser.tcl "tclsh tests\runtests.tcl"
```

`asn1_parser.tcl` currently produces hundreds of operator mutants, so the full
run is intentionally much slower than the normal test suite. Use it as an
occasional test-quality audit rather than a default edit-test loop.

When `deps\protocol-specification` is present, the full suite compiles those
real ASN.1 modules and runs representative BER smoke round-trips via
`tests\protocol_specification.test`.

## Python BER Oracle

For cross-checking BER behavior, this workspace can use Python `asn1tools` as an external oracle.

The oracle dependency is installed into a temporary ignored folder:

```text
.tmp\asn1tools_oracle
```

Install or refresh it with:

```powershell
python -m pip install --target .tmp\asn1tools_oracle asn1tools
```

The current oracle smoke-check script is:

```text
.tmp\asn1tools_oracle_check.py
```

Run it with:

```powershell
python .tmp\asn1tools_oracle_check.py
```

The script compiles the same ASN.1 schema with Python `asn1tools`, compares Python BER encodings against `asn1::ber_encode`, then feeds Python BER bytes into `asn1::ber_decode`.

The `.tmp/` directory is intentionally ignored by Git; it is a local validation aid, not part of the Tcl package.
