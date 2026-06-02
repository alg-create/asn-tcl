set root [pwd]
lappend auto_path $root
package require asn1
set parsed [asn1::parse_str {
    -- Test module for constraints
    ConstraintsModule DEFINITIONS ::= BEGIN
        Age ::= INTEGER (0..120)
        Name ::= PrintableString (SIZE(1..50))
        ExactSize ::= OCTET STRING (SIZE(16))
        Port ::= INTEGER (1024..65535)
        -- Fixed values or alternate sizes
        MagicNumber ::= INTEGER (42)
        IpAddress ::= OCTET STRING (SIZE(4 | 16))
    END}]
puts $parsed
