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
