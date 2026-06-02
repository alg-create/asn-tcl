package require asn1

proc ber_encode_length {len} {
    if {$len < 128} {
        return [binary format c $len]
    }
    set bytes {}
    set temp $len
    while {$temp > 0} {
        set bytes [binary format c [expr {$temp & 0xFF}]]$bytes
        set temp [expr {$temp >> 8}]
    }
    set numBytes [string length $bytes]
    return [binary format c [expr {0x80 | $numBytes}]]$bytes
}

proc ber_encode_integer {val} {
    if {$val == 0} {
        return [binary format c 0]
    }
    set bytes {}
    set temp $val
    for {set i 0} {$i < 8} {incr i} {
        set b [expr {$temp & 0xFF}]
        set bytes [binary format c $b]$bytes
        set temp [expr {$temp >> 8}]
        if {$val > 0 && $temp == 0 && ($b & 0x80) == 0} { break }
        if {$val > 0 && $temp == 0 && ($b & 0x80) != 0} { 
            set bytes [binary format c 0]$bytes
            break 
        }
        if {$val < 0 && $temp == -1 && ($b & 0x80) != 0} { break }
        if {$val < 0 && $temp == -1 && ($b & 0x80) == 0} {
            set bytes [binary format c 255]$bytes
            break
        }
    }
    return $bytes
}

proc asn1::ber_encode {ast moduleName typeName value} {
    set typeDef [dict get $ast $moduleName types $typeName]
    return [ber_encode_type $ast $moduleName $typeDef $value]
}

proc asn1::ber_encode_type {ast moduleName typeDef value} {
    set baseType [dict get $typeDef type]
    
    # Resolve aliases
    while {$baseType ni {"INTEGER" "BOOLEAN" "OCTET STRING" "SEQUENCE" "CHOICE"}} {
        set typeDef [dict get $ast $moduleName types $baseType]
        set baseType [dict get $typeDef type]
    }

    set tagClass "UNIVERSAL"
    set tagNum 0
    
    switch $baseType {
        "INTEGER" {
            set tagNum 2
            set valBytes [::ber_encode_integer $value]
        }
        "BOOLEAN" {
            set tagNum 1
            set valBytes [binary format c [expr {$value ? 0xFF : 0x00}]]
        }
        "OCTET STRING" {
            set tagNum 4
            set valBytes [encoding convertto utf-8 $value]
        }
        "SEQUENCE" {
            set tagNum 16
            set tagClass "UNIVERSAL"
            set valBytes ""
            set comps [dict get $typeDef components]
            dict for {fieldName fieldDef} $comps {
                if {[dict exists $value $fieldName]} {
                    append valBytes [asn1::ber_encode_type $ast $moduleName $fieldDef [dict get $value $fieldName]]
                }
            }
        }
        "CHOICE" {
            # value should be a dict with one key
            set keys [dict keys $value]
            if {[llength $keys] != 1} {
                error "CHOICE value must have exactly one key"
            }
            set chosenField [lindex $keys 0]
            set fieldDef [dict get [dict get $typeDef components] $chosenField]
            return [asn1::ber_encode_type $ast $moduleName $fieldDef [dict get $value $chosenField]]
        }
    }

    # If it's a sequence, we must OR 0x20 to the tag byte for constructed.
    set tagByte $tagNum
    if {$baseType eq "SEQUENCE"} {
        set tagByte [expr {$tagByte | 0x20}]
    }

    # NOTE: Does not handle custom tags yet
    set lenBytes [::ber_encode_length [string length $valBytes]]
    return [binary format c $tagByte]${lenBytes}${valBytes}
}

set schema {
    TestModule DEFINITIONS ::= BEGIN
        MyInt ::= INTEGER
        MyBool ::= BOOLEAN
        MySeq ::= SEQUENCE {
            id INTEGER,
            active BOOLEAN
        }
    END
}
set root [pwd]; lappend auto_path $root; package require asn1
set ast [asn1::parse_str $schema]

puts [binary encode hex [asn1::ber_encode $ast TestModule MyInt 42]]
puts [binary encode hex [asn1::ber_encode $ast TestModule MyBool 1]]
set val [dict create id 255 active 0]
puts [binary encode hex [asn1::ber_encode $ast TestModule MySeq $val]]
