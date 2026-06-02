source ../asn1_parser.tcl

puts "Parsing imports_schema.asn..."
set result [asn1::parse_file "imports_schema.asn"]

puts "Parsed AST:"
puts $result

# Check if Module exists
if {![dict exists $result MyImportModule]} {
    puts "Error: MyImportModule not found in AST"
    exit 1
}

set module [dict get $result MyImportModule]

# Check imports key exists
if {![dict exists $module imports]} {
    puts "Error: imports key not found in module AST"
    exit 1
}

set imports [dict get $module imports]

# 1. Assert SourceModuleA imports
if {![dict exists $imports SourceModuleA]} {
    puts "Error: SourceModuleA not found in imports"
    exit 1
}
set symsA [dict get $imports SourceModuleA]
if {$symsA ne "TypeA TypeB valC"} {
    puts "Error: SourceModuleA imported symbols mismatch. Expected 'TypeA TypeB valC', got: '$symsA'"
    exit 1
}
puts "SourceModuleA imports validated successfully! OK"

# 2. Assert SourceModuleB imports
if {![dict exists $imports SourceModuleB]} {
    puts "Error: SourceModuleB not found in imports"
    exit 1
}
set symsB [dict get $imports SourceModuleB]
if {$symsB ne "TypeD"} {
    puts "Error: SourceModuleB imported symbols mismatch. Expected 'TypeD', got: '$symsB'"
    exit 1
}
puts "SourceModuleB imports validated successfully! OK"

# 3. Assert MySequence exists and parses correctly
set types [dict get $module types]
if {![dict exists $types MySequence]} {
    puts "Error: MySequence not found in types"
    exit 1
}
set seq [dict get $types MySequence]
if {[dict get $seq type] ne "SEQUENCE"} {
    puts "Error: Expected MySequence type to be SEQUENCE"
    exit 1
}
set comps [dict get $seq components]
if {![dict exists $comps field1] || ![dict exists $comps field2]} {
    puts "Error: Components field1 or field2 missing from MySequence"
    exit 1
}
if {[dict get $comps field1 type] ne "TypeA" || [dict get $comps field2 type] ne "TypeD"} {
    puts "Error: MySequence fields type mismatch"
    exit 1
}
puts "MySequence definition validated successfully! OK"

puts "All imports tests passed successfully!"
exit 0
