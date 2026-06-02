source ../asn1_parser.tcl

puts "Parsing test_schema.asn..."
set result [asn1::parse_file "test_schema.asn"]

puts "Parsed AST:"
puts $result

# Verification
if {[dict exists $result MyTestModule]} {
    puts "Module 'MyTestModule' found! OK"
} else {
    puts "Error: Module 'MyTestModule' not found!"
    exit 1
}

set types [dict get $result MyTestModule types]
if {[dict exists $types MyInteger]} {
    if {[dict get $types MyInteger type] eq "INTEGER"} {
        puts "Type 'MyInteger' parsed correctly! OK"
    } else {
        puts "Error: MyInteger type mismatch"
        exit 1
    }
} else {
    puts "Error: MyInteger not found!"
    exit 1
}

if {[dict exists $types MySequence]} {
    if {[dict get $types MySequence type] eq "SEQUENCE"} {
        set comps [dict get $types MySequence components]
        if {[dict exists $comps id] && [dict exists $comps name] && [dict exists $comps isActive]} {
            puts "Type 'MySequence' parsed correctly! OK"
        } else {
            puts "Error: MySequence components missing"
            exit 1
        }
        # Verify extension marker was skipped (no '.' or '...' field name)
        if {[dict exists $comps .] || [dict exists $comps ...]} {
            puts "Error: Extension marker leaked into components as a field!"
            exit 1
        }
        puts "Extension marker correctly skipped! OK"
        # Verify optionalField exists with optional true
        if {[dict exists $comps optionalField]} {
            set optField [dict get $comps optionalField]
            if {[dict get $optField type] eq "BOOLEAN" && [dict exists $optField optional] && [dict get $optField optional]} {
                puts "Field 'optionalField' parsed with OPTIONAL flag! OK"
            } else {
                puts "Error: optionalField missing OPTIONAL flag or wrong type"
                exit 1
            }
        } else {
            puts "Error: optionalField not found in MySequence"
            exit 1
        }
    } else {
        puts "Error: MySequence type mismatch"
        exit 1
    }
} else {
    puts "Error: MySequence not found!"
    exit 1
}

# Verify MyChoice is a separate type (not consumed into MySequence)
if {[dict exists $types MyChoice]} {
    if {[dict get $types MyChoice type] eq "CHOICE"} {
        set choiceComps [dict get $types MyChoice components]
        if {[dict exists $choiceComps opt1] && [dict exists $choiceComps opt2]} {
            puts "Type 'MyChoice' parsed as separate CHOICE type! OK"
        } else {
            puts "Error: MyChoice components missing"
            exit 1
        }
    } else {
        puts "Error: MyChoice type mismatch, got: [dict get $types MyChoice type]"
        exit 1
    }
} else {
    puts "Error: MyChoice not found (possibly consumed by SEQUENCE parsing bug)!"
    exit 1
}

# Verify no parse errors were recorded
if {[dict exists $result MyTestModule errors]} {
    puts "Error: Parse errors found: [dict get $result MyTestModule errors]"
    exit 1
}
puts "No parse errors recorded! OK"

puts "All tests passed successfully!"
exit 0

