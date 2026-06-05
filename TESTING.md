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
test also verifies the project `.tclmut` config and runs TclMut's default
copy-workspace runner against a disposable fixture. The runner test uses a
list-form command with relative paths so the test reads the mutated copy rather
than the original checkout.

## Mutation Testing

The vendored mutation framework lives in `deps\muttcl`. To list mutation
targets from the project config:

```powershell
tclsh deps\muttcl\tclmut.tcl targets
```

To list mutation candidates for the core parser:

```powershell
tclsh deps\muttcl\tclmut.tcl mutants asn1_parser.tcl
```

For real audits of `asn1_parser.tcl`, use the project wrapper instead of the
raw `tclmut run` command:

```powershell
tclsh tools\mutation_audit.tcl -progress-file .tmp\mutation_audit_full.log
```

The wrapper builds a disposable scratch project, mutates the scratch copy of
`asn1_parser.tcl`, runs `tests\mutation_runtests.tcl`, and writes progress
before and after each mutant. This makes long-running audits safe to abort and
easy to inspect while they run.

Watch the log from another PowerShell window:

```powershell
Get-Content .tmp\mutation_audit_full.log -Wait
```

Useful focused runs:

```powershell
tclsh tools\mutation_audit.tcl -mutators arithmetic -progress-file .tmp\mutation_audit_arithmetic.log
tclsh tools\mutation_audit.tcl -mutators arithmetic -limit 10 -progress-file .tmp\mutation_audit_arithmetic.log
tclsh tools\mutation_audit.tcl -mutators arithmetic -start 11 -progress-file .tmp\mutation_audit_arithmetic.log
```

The project `.tclmut` file currently targets `asn1_parser.tcl`, enables all
supported mutator categories, and sets a fixed mutation timeout for raw TclMut
runs. The full audit is intentionally much slower than the normal test suite, so
use it as an occasional test-quality audit rather than a default edit-test loop.

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
