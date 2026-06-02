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
    } else {
        puts "Error: MySequence type mismatch"
        exit 1
    }
} else {
    puts "Error: MySequence not found!"
    exit 1
}

puts "All tests passed successfully!"
exit 0
