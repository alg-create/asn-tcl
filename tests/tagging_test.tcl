source ../asn1_parser.tcl

puts "Parsing tagging_schema.asn..."
set result [asn1::parse_file "tagging_schema.asn"]

puts "Parsed AST:"
puts $result

# Check if Module exists
if {![dict exists $result MyTaggedModule]} {
    puts "Error: MyTaggedModule not found in AST"
    exit 1
}

set module [dict get $result MyTaggedModule]

# Check Global default tagging
if {[dict get $module tagging] ne "IMPLICIT"} {
    puts "Error: Expected tagging default to be IMPLICIT, got: [dict get $module tagging]"
    exit 1
}
puts "Module level tagging matches 'IMPLICIT'! OK"

set types [dict get $module types]

# Helper proc to assert tag values
proc assert_tag {types typeName expectedClass expectedNumber expectedMode} {
    if {![dict exists $types $typeName]} {
        puts "Error: Type $typeName not found"
        exit 1
    }
    
    set typeDef [dict get $types $typeName]
    if {![dict exists $typeDef tag]} {
        puts "Error: Type $typeName has no tag definition"
        exit 1
    }
    
    set tag [dict get $typeDef tag]
    if {[dict get $tag class] ne $expectedClass} {
        puts "Error: $typeName class mismatch. Expected '$expectedClass', got '[dict get $tag class]'"
        exit 1
    }
    if {[dict get $tag number] != $expectedNumber} {
        puts "Error: $typeName number mismatch. Expected '$expectedNumber', got '[dict get $tag number]'"
        exit 1
    }
    
    if {$expectedMode eq ""} {
        if {[dict exists $tag mode]} {
            puts "Error: $typeName should not have mode, but got '[dict get $tag mode]'"
            exit 1
        }
    } else {
        if {![dict exists $tag mode] || [dict get $tag mode] ne $expectedMode} {
            set gotMode [expr {[dict exists $tag mode] ? [dict get $tag mode] : "none"}]
            puts "Error: $typeName mode mismatch. Expected '$expectedMode', got '$gotMode'"
            exit 1
        }
    }
    
    puts "Type '$typeName' tag validated successfully! OK"
}

# 1. Verify global / type-level tagging
assert_tag $types GlobalTaggedType APPLICATION 2 IMPLICIT
assert_tag $types ExplicitTaggedType UNIVERSAL 10 EXPLICIT
assert_tag $types DefaultTaggedType PRIVATE 5 ""

# 2. Verify TaggedSequence members
if {![dict exists $types TaggedSequence]} {
    puts "Error: TaggedSequence not found"
    exit 1
}
set seq [dict get $types TaggedSequence]
set comps [dict get $seq components]

# standardMember should not have a tag
if {![dict exists $comps standardMember]} {
    puts "Error: standardMember not found in TaggedSequence"
    exit 1
}
if {[dict exists $comps standardMember tag]} {
    puts "Error: standardMember should not have tag metadata"
    exit 1
}
puts "standardMember has no tag (as expected)! OK"

# customMember should have private 14 implicit tag
if {![dict exists $comps customMember]} {
    puts "Error: customMember not found in TaggedSequence"
    exit 1
}
set customMemberTag [dict get $comps customMember tag]
if {[dict get $customMemberTag class] ne "PRIVATE" || [dict get $customMemberTag number] != 14 || [dict get $customMemberTag mode] ne "IMPLICIT"} {
    puts "Error: customMember tag mismatch: $customMemberTag"
    exit 1
}
puts "customMember tag validated successfully! OK"

# 3. Verify TaggedChoice members
if {![dict exists $types TaggedChoice]} {
    puts "Error: TaggedChoice not found"
    exit 1
}
set choice [dict get $types TaggedChoice]
set choiceComps [dict get $choice components]

# choiceA should have CONTEXT-SPECIFIC 1 implicit tag
if {![dict exists $choiceComps choiceA]} {
    puts "Error: choiceA not found in TaggedChoice"
    exit 1
}
set choiceATag [dict get $choiceComps choiceA tag]
if {[dict get $choiceATag class] ne "CONTEXT-SPECIFIC" || [dict get $choiceATag number] != 1 || [dict get $choiceATag mode] ne "IMPLICIT"} {
    puts "Error: choiceA tag mismatch: $choiceATag"
    exit 1
}
puts "choiceA tag validated successfully! OK"

# choiceB should have CONTEXT-SPECIFIC 2 explicit tag
if {![dict exists $choiceComps choiceB]} {
    puts "Error: choiceB not found in TaggedChoice"
    exit 1
}
set choiceBTag [dict get $choiceComps choiceB tag]
if {[dict get $choiceBTag class] ne "CONTEXT-SPECIFIC" || [dict get $choiceBTag number] != 2 || [dict get $choiceBTag mode] ne "EXPLICIT"} {
    puts "Error: choiceB tag mismatch: $choiceBTag"
    exit 1
}
puts "choiceB tag validated successfully! OK"

puts "All tagging tests passed successfully!"
exit 0
