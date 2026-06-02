#!/usr/bin/env tclsh
# Error cases and edge cases test suite for the ASN.1 parser.
# Each test exercises a specific failure mode and verifies the parser
# handles it gracefully (no crash, no hang, correct error reporting).

source ../asn1_parser.tcl

set total 0
set passed 0
set failed 0

proc run_test {name body} {
    upvar total total passed passed failed failed
    incr total
    puts -nonewline "  $name ... "
    if {[catch {uplevel 1 $body} err]} {
        puts "FAIL ($err)"
        incr failed
    } else {
        puts "OK"
        incr passed
    }
}

proc assert {cond msg} {
    if {![uplevel 1 [list expr $cond]]} {
        error $msg
    }
}

puts "========================================"
puts "  Error Cases and Edge Cases Test Suite"
puts "========================================"

# --- Test 1: Empty input ---
run_test "Empty input returns empty AST" {
    set result [asn1::parse [asn1::tokenize ""]]
    assert {$result eq ""} "Expected empty dict, got: $result"
}

# --- Test 2: Garbage input ---
run_test "Garbage input returns empty AST, no crash" {
    set result [asn1::parse [asn1::tokenize "!@#\$%^&* hello world 12345"]]
    assert {$result eq "" || [llength $result] == 0} "Expected empty dict, got: $result"
}

# --- Test 3: Missing END keyword ---
run_test "Missing END keyword records error" {
    set input "TestMod DEFINITIONS ::= BEGIN MyType ::= INTEGER"
    set result [asn1::parse [asn1::tokenize $input]]
    assert {[dict exists $result TestMod]} "Module TestMod not found"
    assert {[dict exists $result TestMod errors]} "Expected errors to be recorded"
    set errors [dict get $result TestMod errors]
    assert {[string match "*missing END*" [string tolower [join $errors]]]} \
        "Expected 'missing END' error, got: $errors"
    # Type should still be parsed
    assert {[dict get $result TestMod types MyType type] eq "INTEGER"} \
        "MyType should still be parsed"
}

# --- Test 4: Missing BEGIN keyword ---
run_test "Missing BEGIN keyword skips module, no crash" {
    set input "TestMod DEFINITIONS ::= NOTBEGIN MyType ::= INTEGER END"
    set result [asn1::parse [asn1::tokenize $input]]
    # Module should not be created since BEGIN was not found
    assert {![dict exists $result TestMod]} "Module should not be parsed without BEGIN"
}

# --- Test 5: Empty module ---
run_test "Empty module (no type definitions)" {
    set input "EmptyMod DEFINITIONS ::= BEGIN END"
    set result [asn1::parse [asn1::tokenize $input]]
    assert {[dict exists $result EmptyMod]} "EmptyMod not found"
    set types [dict get $result EmptyMod types]
    assert {$types eq ""} "Expected empty types dict, got: $types"
    assert {![dict exists $result EmptyMod errors]} "Should have no errors"
}

# --- Test 6: Empty SEQUENCE ---
run_test "Empty SEQUENCE produces empty components" {
    set input "Mod DEFINITIONS ::= BEGIN EmptySeq ::= SEQUENCE \{\} END"
    set result [asn1::parse [asn1::tokenize $input]]
    assert {[dict exists $result Mod]} "Mod not found"
    set comps [dict get $result Mod types EmptySeq components]
    assert {$comps eq ""} "Expected empty components, got: $comps"
}

# --- Test 7: Extension markers in SEQUENCE ---
run_test "Extension markers skipped in SEQUENCE" {
    set input {ExtMod DEFINITIONS ::= BEGIN
        ExtSeq ::= SEQUENCE {
            field1 INTEGER,
            ...,
            field2 BOOLEAN
        }
    END}
    set result [asn1::parse [asn1::tokenize $input]]
    set comps [dict get $result ExtMod types ExtSeq components]
    assert {[dict exists $comps field1]} "field1 missing"
    assert {[dict exists $comps field2]} "field2 missing"
    assert {![dict exists $comps .]} "Dot leaked as field name"
    assert {![dict exists $comps ...]} "Extension marker leaked as field name"
}

# --- Test 8: OPTIONAL keyword on fields ---
run_test "OPTIONAL keyword sets optional flag" {
    set input {OptMod DEFINITIONS ::= BEGIN
        OptSeq ::= SEQUENCE {
            required INTEGER,
            maybe BOOLEAN OPTIONAL
        }
    END}
    set result [asn1::parse [asn1::tokenize $input]]
    set comps [dict get $result OptMod types OptSeq components]
    assert {![dict exists $comps required optional]} "required should not have optional flag"
    assert {[dict exists $comps maybe optional]} "maybe should have optional flag"
    assert {[dict get $comps maybe optional] == true} "optional flag should be true"
}

# --- Test 9: DEFAULT keyword on fields ---
run_test "DEFAULT keyword captures default value" {
    set input {DefMod DEFINITIONS ::= BEGIN
        DefSeq ::= SEQUENCE {
            status INTEGER DEFAULT 0,
            name OCTET STRING
        }
    END}
    set result [asn1::parse [asn1::tokenize $input]]
    set comps [dict get $result DefMod types DefSeq components]
    assert {[dict exists $comps status default]} "status should have default"
    assert {[dict get $comps status default] eq "0"} \
        "Expected default 0, got: [dict get $comps status default]"
    assert {![dict exists $comps name default]} "name should not have default"
}

# --- Test 10: Unclosed SEQUENCE brace ---
run_test "Unclosed SEQUENCE brace records error" {
    set input "Mod DEFINITIONS ::= BEGIN BadSeq ::= SEQUENCE \{ f1 INTEGER END"
    set result [asn1::parse [asn1::tokenize $input]]
    assert {[dict exists $result Mod]} "Mod not found"
    assert {[dict exists $result Mod errors]} "Expected errors to be recorded"
    # f1 should still be in the partial parse
    assert {[dict exists $result Mod types BadSeq components f1]} "f1 should still be parsed"
}

# --- Test 11: IMPORTS without semicolon ---
run_test "IMPORTS without semicolon records error" {
    set input "Mod DEFINITIONS ::= BEGIN IMPORTS TypeA FROM OtherMod MyType ::= INTEGER END"
    set result [asn1::parse [asn1::tokenize $input]]
    assert {[dict exists $result Mod]} "Mod not found"
    assert {[dict exists $result Mod errors]} "Expected errors for missing semicolon"
}

# --- Test 12: Multiple modules in one input ---
run_test "Multiple modules parsed correctly" {
    set input {
        ModA DEFINITIONS ::= BEGIN TypeA ::= INTEGER END
        ModB DEFINITIONS ::= BEGIN TypeB ::= BOOLEAN END
    }
    set result [asn1::parse [asn1::tokenize $input]]
    assert {[dict exists $result ModA]} "ModA not found"
    assert {[dict exists $result ModB]} "ModB not found"
    assert {[dict get $result ModA types TypeA type] eq "INTEGER"} "TypeA mismatch"
    assert {[dict get $result ModB types TypeB type] eq "BOOLEAN"} "TypeB mismatch"
}

# --- Test 13: Tokenizer produces ... and .. as single tokens ---
run_test "Tokenizer: ... emitted as single token" {
    set tokens [asn1::tokenize "..."]
    assert {[llength $tokens] == 1 && [lindex $tokens 0] eq "..."} \
        "Expected single '...' token, got: $tokens"
}

run_test "Tokenizer: .. emitted as single token" {
    set tokens [asn1::tokenize "1..100"]
    assert {[lindex $tokens 0] eq "1"} "Expected '1'"
    assert {[lindex $tokens 1] eq ".."} "Expected '..', got: [lindex $tokens 1]"
    assert {[lindex $tokens 2] eq "100"} "Expected '100'"
}

# --- Test 14: Double extension markers ---
run_test "Double extension markers in SEQUENCE" {
    set input {Mod DEFINITIONS ::= BEGIN
        Seq ::= SEQUENCE {
            f1 INTEGER,
            ...,
            f2 BOOLEAN,
            ...
        }
    END}
    set result [asn1::parse [asn1::tokenize $input]]
    set comps [dict get $result Mod types Seq components]
    assert {[dict exists $comps f1]} "f1 missing"
    assert {[dict exists $comps f2]} "f2 missing"
    assert {[dict size $comps] == 2} "Expected exactly 2 fields, got [dict size $comps]"
}

# --- Test 15: Tagged field with OPTIONAL ---
run_test "Tagged field combined with OPTIONAL" {
    set input {Mod DEFINITIONS ::= BEGIN
        Seq ::= SEQUENCE {
            name  [0] IMPLICIT OCTET STRING OPTIONAL,
            age   INTEGER
        }
    END}
    set result [asn1::parse [asn1::tokenize $input]]
    set comps [dict get $result Mod types Seq components]
    assert {[dict exists $comps name tag]} "name should have tag"
    assert {[dict get $comps name optional] == true} "name should be optional"
    assert {[dict get $comps name type] eq "OCTET STRING"} \
        "Expected OCTET STRING, got: [dict get $comps name type]"
}

puts "========================================"
puts "Summary: $total tests, $passed passed, $failed failed"
puts "========================================"

if {$failed > 0} {
    exit 1
} else {
    exit 0
}
