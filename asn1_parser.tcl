package provide asn1 0.2.0

namespace eval asn1 {
    namespace export parse_file parse_str ber_encode ber_decode
}

# Tokenize the ASN.1 text into a list of tokens
proc asn1::tokenize {text} {
    # Remove block comments /* ... */
    regsub -all -- {/\*.*?\*/} $text "" text

    # Remove line comments -- ... -- or -- ... \n
    regsub -all -- {--.*?(--|\n|$)} $text "\n" text

    # Find tokens
    set tokens {}
    set length [string length $text]
    set i 0
    while {$i < $length} {
        set ch [string index $text $i]

        if {[string is space $ch]} {
            incr i
            continue
        }

        # Match ::=
        if {[string match "::=" [string range $text $i [expr {$i+2}]]]} {
            lappend tokens "::="
            incr i 3
            continue
        }

        # Match ... (extension marker) before .. (range) before single .
        if {$ch eq "."} {
            if {[string range $text $i [expr {$i+2}]] eq "..."} {
                lappend tokens "..."
                incr i 3
                continue
            }
            if {[string range $text $i [expr {$i+1}]] eq ".."} {
                lappend tokens ".."
                incr i 2
                continue
            }
            lappend tokens "."
            incr i
            continue
        }

        # Match punctuation (excluding dot, handled above)
        if {[string first $ch "{}()\[\],;|"] != -1} {
            lappend tokens $ch
            incr i
            continue
        }

        # Match word token (letters, numbers, hyphens)
        if {[regexp -start $i -indices {[a-zA-Z0-9_-]+} $text matchIdx]} {
            if {[lindex $matchIdx 0] == $i} {
                set endIdx [lindex $matchIdx 1]
                lappend tokens [string range $text $i $endIdx]
                set i [expr {$endIdx + 1}]
                continue
            }
        }

        # Match string literals "..."
        if {$ch eq "\""} {
            if {[regexp -start $i -indices "\"\[^\"\]*\"" $text matchIdx]} {
                if {[lindex $matchIdx 0] == $i} {
                    set endIdx [lindex $matchIdx 1]
                    lappend tokens [string range $text $i $endIdx]
                    set i [expr {$endIdx + 1}]
                    continue
                }
            }
        }

        # Unrecognized character, just skip
        incr i
    }

    return $tokens
}

# Parse optional tag if present at current index in tokens.
# Updates the index variable in the caller's scope if a tag was parsed.
# Returns the tag dict, or empty list if no tag was found.
proc asn1::parse_tag_optional {tokensVar indexVar} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar idx
    set len [llength $tokens]

    if {$idx >= $len || [lindex $tokens $idx] ne "\["} {
        return {}
    }

    # Tag starts at idx
    set saveIdx $idx
    incr idx ;# skip '['

    if {$idx >= $len} {
        set idx $saveIdx
        return {}
    }

    set tagClass "CONTEXT-SPECIFIC"
    set token [lindex $tokens $idx]
    if {$token in {"UNIVERSAL" "APPLICATION" "PRIVATE"}} {
        set tagClass $token
        incr idx
    }

    if {$idx >= $len} {
        set idx $saveIdx
        return {}
    }

    set tagNum [lindex $tokens $idx]
    incr idx ;# skip number

    # skip ']'
    if {$idx < $len && [lindex $tokens $idx] eq "\]"} {
        incr idx
    } else {
        # Invalid tag structure, backtrack
        set idx $saveIdx
        return {}
    }

    # Check for optional IMPLICIT/EXPLICIT
    set tagMode ""
    if {$idx < $len} {
        set nextTok [lindex $tokens $idx]
        if {$nextTok in {"IMPLICIT" "EXPLICIT"}} {
            set tagMode $nextTok
            incr idx
        }
    }

    set tag [dict create class $tagClass number $tagNum]
    if {$tagMode ne ""} {
        dict set tag mode $tagMode
    }

    return $tag
}


# Parse the components (fields) inside a SEQUENCE or CHOICE block.
# Reads tokens from the current index until closing brace.
# Handles extension markers (...), OPTIONAL, DEFAULT, tags, and
# multi-word types (OCTET STRING, BIT STRING).
# Appends any errors to the errorsVar list in the caller.
proc asn1::parse_components {tokensVar indexVar errorsVar} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    upvar 1 $errorsVar errors
    set len [llength $tokens]
    set fields [dict create]

    while {$i < $len && [lindex $tokens $i] ne "\}"} {
        # Skip extension markers
        if {[lindex $tokens $i] eq "..."} {
            incr i
            if {$i < $len && [lindex $tokens $i] eq ","} {
                incr i
            }
            continue
        }

        set fieldName [lindex $tokens $i]
        incr i

        if {$i >= $len || [lindex $tokens $i] eq "\}"} {
            lappend errors "Unexpected end of component list after field name '$fieldName'"
            break
        }

        # Check for optional tag on the member/component
        set memberTag [asn1::parse_tag_optional tokens i]

        if {$i >= $len || [lindex $tokens $i] eq "\}"} {
            lappend errors "Missing type for field '$fieldName'"
            break
        }

        set fieldType [lindex $tokens $i]

        # Handle OCTET STRING, BIT STRING
        if {$fieldType in {"OCTET" "BIT"} && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "STRING"} {
            set fieldType "$fieldType STRING"
            incr i
        }

        set fieldInfo [dict create type $fieldType]
        if {$memberTag ne {}} {
            dict set fieldInfo tag $memberTag
        }
        incr i

        # Handle OPTIONAL keyword
        if {$i < $len && [lindex $tokens $i] eq "OPTIONAL"} {
            dict set fieldInfo optional true
            incr i
        }

        # Handle DEFAULT keyword and its value
        if {$i < $len && [lindex $tokens $i] eq "DEFAULT"} {
            incr i
            if {$i < $len && [lindex $tokens $i] ni {"," "\}" "..."}} {
                dict set fieldInfo default [lindex $tokens $i]
                incr i
            }
        }

        dict set fields $fieldName $fieldInfo
        if {$i < $len && [lindex $tokens $i] eq ","} {
            incr i
        }
    }

    return $fields
}

# Parse a token stream into an AST
proc asn1::parse {tokens} {
    set ast [dict create]
    set len [llength $tokens]
    set i 0

    while {$i < $len} {
        set token [lindex $tokens $i]

        # Look for Module Definition: ModuleName DEFINITIONS ... ::= BEGIN
        if {$i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "DEFINITIONS"} {
            set moduleName $token
            set tagging_ "EXPLICIT" ;# default default
            set errors {}

            set searchIdx [expr {$i + 2}]
            # Check for optional tagging environment
            if {$searchIdx < $len && [lindex $tokens $searchIdx] in {"EXPLICIT" "IMPLICIT" "AUTOMATIC"}} {
                if {$searchIdx + 1 < $len && [lindex $tokens [expr {$searchIdx+1}]] eq "TAGS"} {
                    set tagging_ [lindex $tokens $searchIdx]
                    incr searchIdx 2
                }
            }

            if {$searchIdx + 1 < $len && [lindex $tokens $searchIdx] eq "::=" && [lindex $tokens [expr {$searchIdx+1}]] eq "BEGIN"} {
                set moduleAst [dict create tagging $tagging_ imports [dict create] types [dict create] values [dict create]]
                set i [expr {$searchIdx + 2}]

                # Parse IMPORTS block if present
                if {$i < $len && [lindex $tokens $i] eq "IMPORTS"} {
                    incr i ;# skip "IMPORTS"
                    set importsDict [dict create]
                    while {$i < $len && [lindex $tokens $i] ne ";" && [lindex $tokens $i] ne "END"} {
                        # Read list of symbols until FROM
                        set symbols {}
                        while {$i < $len && [lindex $tokens $i] ni {"FROM" ";" "END"}} {
                            set sym [lindex $tokens $i]
                            if {$sym ne ","} {
                                lappend symbols $sym
                            }
                            incr i
                        }
                        if {$i < $len && [lindex $tokens $i] eq "FROM"} {
                            incr i ;# skip "FROM"
                            if {$i < $len} {
                                set fromModule [lindex $tokens $i]
                                incr i ;# skip module name
                                dict set importsDict $fromModule $symbols
                            }
                        }
                    }
                    if {$i < $len && [lindex $tokens $i] eq ";"} {
                        incr i ;# skip ";"
                    } else {
                        lappend errors "IMPORTS block missing terminating semicolon"
                    }
                    dict set moduleAst imports $importsDict
                }

                # Parse body of module
                while {$i < $len && [lindex $tokens $i] ne "END"} {
                    set ident [lindex $tokens $i]

                    if {$i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "::="} {
                        set tempIdx [expr {$i + 2}]
                        if {$tempIdx >= $len} {
                            lappend errors "Unexpected end of input after '::=' for type '$ident'"
                            incr i
                            continue
                        }
                        set tagDict [asn1::parse_tag_optional tokens tempIdx]
                        set rhsToken [lindex $tokens $tempIdx]

                        if {$rhsToken eq "SEQUENCE" && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "\{"} {
                            # Parse SEQUENCE
                            set i [expr {$tempIdx + 2}]
                            set fields [asn1::parse_components tokens i errors]
                            dict set moduleAst types $ident type "SEQUENCE"
                            if {$tagDict ne {}} {
                                dict set moduleAst types $ident tag $tagDict
                            }
                            dict set moduleAst types $ident components $fields
                            if {$i < $len && [lindex $tokens $i] eq "\}"} {
                                incr i ;# skip closing brace
                            } else {
                                lappend errors "Missing closing brace for SEQUENCE '$ident'"
                            }
                        } elseif {$rhsToken eq "CHOICE" && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "\{"} {
                            # Parse CHOICE
                            set i [expr {$tempIdx + 2}]
                            set fields [asn1::parse_components tokens i errors]
                            dict set moduleAst types $ident type "CHOICE"
                            if {$tagDict ne {}} {
                                dict set moduleAst types $ident tag $tagDict
                            }
                            dict set moduleAst types $ident components $fields
                            if {$i < $len && [lindex $tokens $i] eq "\}"} {
                                incr i ;# skip closing brace
                            } else {
                                lappend errors "Missing closing brace for CHOICE '$ident'"
                            }
                        } else {
                            # Simple type assignment
                            set fieldType $rhsToken
                            if {$fieldType in {"OCTET" "BIT"} && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "STRING"} {
                                set fieldType "$fieldType STRING"
                                set i [expr {$tempIdx + 2}]
                            } else {
                                set i [expr {$tempIdx + 1}]
                            }
                            dict set moduleAst types $ident type $fieldType
                            if {$tagDict ne {}} {
                                dict set moduleAst types $ident tag $tagDict
                            }
                            # Parse constraints
                            if {$i < $len && [lindex $tokens $i] eq "("} {
                                set constraintDict [dict create]
                                incr i ;# skip '('
                                if {$i < $len && [lindex $tokens $i] eq "SIZE"} {
                                    incr i ;# skip 'SIZE'
                                    if {$i < $len && [lindex $tokens $i] eq "("} {
                                        incr i ;# skip '('
                                        set sizeList {}
                                        while {$i < $len && [lindex $tokens $i] ne ")"} {
                                            set tok [lindex $tokens $i]
                                            if {$tok ne ".."} {
                                                lappend sizeList $tok
                                            }
                                            incr i
                                        }
                                        if {[llength $sizeList] == 1} {
                                            dict set constraintDict SIZE [lindex $sizeList 0]
                                        } else {
                                            dict set constraintDict SIZE $sizeList
                                        }
                                        if {$i < $len && [lindex $tokens $i] eq ")"} {
                                            incr i ;# skip ')'
                                        }
                                    }
                                } else {
                                    set rangeList {}
                                    while {$i < $len && [lindex $tokens $i] ne ")"} {
                                        set tok [lindex $tokens $i]
                                        if {$tok ne ".."} {
                                            lappend rangeList $tok
                                        }
                                        incr i
                                    }
                                    if {[llength $rangeList] == 1} {
                                        dict set constraintDict RANGE [lindex $rangeList 0]
                                    } else {
                                        dict set constraintDict RANGE $rangeList
                                    }
                                }
                                if {$i < $len && [lindex $tokens $i] eq ")"} {
                                    incr i ;# skip ')'
                                }
                                dict set moduleAst types $ident constraints $constraintDict
                            }
                        }
                    } else {
                        incr i
                    }
                }

                if {$i < $len && [lindex $tokens $i] eq "END"} {
                    incr i
                } else {
                    lappend errors "Module '$moduleName' missing END keyword"
                }
                if {[llength $errors] > 0} {
                    dict set moduleAst errors_ $errors
                }
                dict set ast $moduleName $moduleAst
            } else {
                incr i
            }
        } else {
            incr i
        }
    }

    return $ast
}

proc asn1::parse_file {filepath} {
    set fp [open $filepath r]
    set data [read $fp]
    close $fp
    return [asn1::parse_str $data]
}

proc asn1::parse_str {moduleText} {
    return [asn1::parse [asn1::tokenize $moduleText]]
}

# --- BER Encoder ---

proc asn1::ber_encode_length {len} {
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

proc asn1::ber_encode_integer {val} {
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
    return [asn1::ber_encode_type $ast $moduleName $typeDef $value]
}

proc asn1::ber_encode_type {ast moduleName typeDef value} {
    set baseType [dict get $typeDef type]
    while {$baseType ni {"INTEGER" "BOOLEAN" "OCTET STRING" "SEQUENCE" "CHOICE"}} {
        set typeDef [dict get $ast $moduleName types $baseType]
        set baseType [dict get $typeDef type]
    }

    set tagNum 0
    switch $baseType {
        "INTEGER" {
            set tagNum 2
            set valBytes [asn1::ber_encode_integer $value]
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
            set valBytes ""
            set comps [dict get $typeDef components]
            dict for {fieldName fieldDef} $comps {
                if {[dict exists $value $fieldName]} {
                    append valBytes [asn1::ber_encode_type $ast $moduleName $fieldDef [dict get $value $fieldName]]
                }
            }
        }
        "CHOICE" {
            set keys [dict keys $value]
            if {[llength $keys] != 1} { error "CHOICE value must have exactly one key" }
            set chosenField [lindex $keys 0]
            set fieldDef [dict get [dict get $typeDef components] $chosenField]
            return [asn1::ber_encode_type $ast $moduleName $fieldDef [dict get $value $chosenField]]
        }
    }

    set tagByte $tagNum
    if {$baseType eq "SEQUENCE"} {
        set tagByte [expr {$tagByte | 0x20}]
    }

    set lenBytes [asn1::ber_encode_length [string length $valBytes]]
    return [binary format c $tagByte]${lenBytes}${valBytes}
}

# --- BER Decoder ---

proc asn1::ber_decode_length {bytes idxVar} {
    upvar 1 $idxVar idx
    binary scan [string index $bytes $idx] c b
    set b [expr {$b & 0xFF}]
    incr idx
    if {$b < 128} {
        return $b
    }
    set numBytes [expr {$b & 0x7F}]
    set len 0
    for {set i 0} {$i < $numBytes} {incr i} {
        binary scan [string index $bytes $idx] c b
        set b [expr {$b & 0xFF}]
        incr idx
        set len [expr {($len << 8) | $b}]
    }
    return $len
}

proc asn1::ber_decode_integer {bytes} {
    set len [string length $bytes]
    if {$len == 0} { return 0 }
    binary scan [string index $bytes 0] c firstByte
    set val 0
    if {$firstByte & 0x80} {
        set val -1
    }
    for {set i 0} {$i < $len} {incr i} {
        binary scan [string index $bytes $i] c b
        set b [expr {$b & 0xFF}]
        set val [expr {($val << 8) | $b}]
    }
    return $val
}

proc asn1::get_expected_tag {ast moduleName typeDef} {
    set baseType [dict get $typeDef type]
    while {$baseType ni {"INTEGER" "BOOLEAN" "OCTET STRING" "SEQUENCE" "CHOICE"}} {
        set typeDef [dict get $ast $moduleName types $baseType]
        set baseType [dict get $typeDef type]
    }
    switch $baseType {
        "INTEGER" { return 2 }
        "BOOLEAN" { return 1 }
        "OCTET STRING" { return 4 }
        "SEQUENCE" { return [expr {16 | 0x20}] }
        "CHOICE" { return -1 }
    }
}

proc asn1::ber_decode {ast moduleName typeName bytes} {
    set typeDef [dict get $ast $moduleName types $typeName]
    set idx 0
    set val [asn1::ber_decode_type $ast $moduleName $typeDef $bytes idx]
    set remainder [string range $bytes $idx end]
    return [dict create value $val remainder $remainder]
}

proc asn1::ber_decode_type {ast moduleName typeDef bytes idxVar} {
    upvar 1 $idxVar idx

    set baseType [dict get $typeDef type]
    while {$baseType ni {"INTEGER" "BOOLEAN" "OCTET STRING" "SEQUENCE" "CHOICE"}} {
        set typeDef [dict get $ast $moduleName types $baseType]
        set baseType [dict get $typeDef type]
    }

    if {$baseType eq "CHOICE"} {
        binary scan [string index $bytes $idx] c tagByte
        set tagByte [expr {$tagByte & 0xFF}]
        set comps [dict get $typeDef components]
        dict for {fieldName fieldDef} $comps {
            set expectedTag [asn1::get_expected_tag $ast $moduleName $fieldDef]
            if {$tagByte == $expectedTag} {
                return [dict create $fieldName [asn1::ber_decode_type $ast $moduleName $fieldDef $bytes idx]]
            }
        }
        error "No matching tag $tagByte in CHOICE"
    }

    binary scan [string index $bytes $idx] c tagByte
    set tagByte [expr {$tagByte & 0xFF}]
    incr idx

    set len [asn1::ber_decode_length $bytes idx]
    set valBytes [string range $bytes $idx [expr {$idx + $len - 1}]]
    incr idx $len

    switch $baseType {
        "INTEGER" { return [asn1::ber_decode_integer $valBytes] }
        "BOOLEAN" {
            binary scan [string index $valBytes 0] c b
            return [expr {($b & 0xFF) != 0}]
        }
        "OCTET STRING" { return $valBytes }
        "SEQUENCE" {
            set result [dict create]
            set subIdx 0
            set comps [dict get $typeDef components]
            dict for {fieldName fieldDef} $comps {
                if {$subIdx >= $len} {
                    if {[dict exists $fieldDef optional] && [dict get $fieldDef optional]} { continue }
                    if {[dict exists $fieldDef default]} {
                        dict set result $fieldName [dict get $fieldDef default]
                        continue
                    }
                    error "Missing mandatory field $fieldName"
                }
                set fieldVal [asn1::ber_decode_type $ast $moduleName $fieldDef $valBytes subIdx]
                dict set result $fieldName $fieldVal
            }
            return $result
        }
    }
}
