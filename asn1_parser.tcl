package provide asn1 0.2.0

namespace eval asn1 {
    namespace export parse_file parse_files parse_str ber_encode ber_decode ber_encode_value
    namespace export ber_encode_tag ber_encode_length ber_decode_tag ber_decode_length
    namespace export ber_encode_tlv ber_decode_tlv ber_wrap_context ber_wrap_application ber_wrap_private
    namespace export ber_encode_integer_tlv ber_encode_boolean_tlv ber_encode_utf8_string_tlv
    namespace export ber_encode_null_tlv ber_encode_sequence_tlv ber_encode_set_tlv
    namespace export ber_read_tlv ber_read_sequence
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
        if {[string first $ch "{}()\[\],;|:"] != -1} {
            lappend tokens $ch
            incr i
            continue
        }

        # Match binary and hex string literals, e.g. '0101'B and '0A3F'H.
        if {$ch eq "'"} {
            set start $i
            incr i
            set literal ""
            while {$i < $length && [string index $text $i] ne "'"} {
                append literal [string index $text $i]
                incr i
            }
            if {$i >= $length} {
                error "Unterminated ASN.1 binary/hex string literal at index $start"
            }
            incr i
            if {$i >= $length || [string toupper [string index $text $i]] ni {"B" "H"}} {
                error "ASN.1 binary/hex string literal at index $start must end with B or H"
            }
            set suffix [string toupper [string index $text $i]]
            if {$suffix eq "B" && ![regexp {^[01[:space:]]*$} $literal]} {
                error "Invalid binary string literal at index $start"
            }
            if {$suffix eq "H" && ![regexp {^[0-9A-Fa-f[:space:]]*$} $literal]} {
                error "Invalid hex string literal at index $start"
            }
            lappend tokens "'$literal'$suffix"
            incr i
            continue
        }

        # Match string literals, including ASN.1 doubled quotes and
        # backslash-escaped quote characters.
        if {$ch eq "\""} {
            set start $i
            incr i
            set closed 0
            while {$i < $length} {
                set curr [string index $text $i]
                if {$curr eq "\\"} {
                    incr i 2
                    continue
                }
                if {$curr eq "\""} {
                    if {$i + 1 < $length && [string index $text [expr {$i+1}]] eq "\""} {
                        incr i 2
                        continue
                    }
                    incr i
                    set closed 1
                    break
                }
                incr i
            }
            if {!$closed} {
                error "Unterminated ASN.1 character string literal at index $start"
            }
            lappend tokens [string range $text $start [expr {$i - 1}]]
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

        error "Unknown character '$ch' at index $i"
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

proc asn1::parse_named_number_list {tokensVar indexVar errorsVar} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    upvar 1 $errorsVar errors
    set len [llength $tokens]
    set values [dict create]

    if {$i >= $len || [lindex $tokens $i] ne "\{"} {
        return $values
    }

    incr i
    while {$i < $len && [lindex $tokens $i] ne "\}"} {
        set name [lindex $tokens $i]
        incr i

        if {$i < $len && [lindex $tokens $i] eq "("} {
            incr i
            if {$i < $len} {
                set number [lindex $tokens $i]
                incr i
                dict set values $name $number
            } else {
                lappend errors "Missing number for named value '$name'"
                break
            }
            if {$i < $len && [lindex $tokens $i] eq ")"} {
                incr i
            } else {
                lappend errors "Missing closing parenthesis for named value '$name'"
                break
            }
        } else {
            lappend errors "Missing number for named value '$name'"
            break
        }

        if {$i < $len && [lindex $tokens $i] eq ","} {
            incr i
        }
    }

    if {$i < $len && [lindex $tokens $i] eq "\}"} {
        incr i
    } else {
        lappend errors "Missing closing brace for named number list"
    }

    return $values
}

proc asn1::parse_constraint_optional {tokensVar indexVar} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    set len [llength $tokens]
    set constraintDict [dict create]

    if {$i >= $len || [lindex $tokens $i] ne "("} {
        return $constraintDict
    }

    incr i
    if {$i < $len && [lindex $tokens $i] eq "SIZE"} {
        incr i
        if {$i < $len && [lindex $tokens $i] eq "("} {
            incr i
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
                incr i
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
        incr i
    }

    return $constraintDict
}

proc asn1::parse_bare_size_constraint_optional {tokensVar indexVar} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    set len [llength $tokens]
    set constraintDict [dict create]

    if {$i >= $len || [lindex $tokens $i] ne "SIZE"} {
        return $constraintDict
    }

    incr i
    if {$i < $len && [lindex $tokens $i] eq "("} {
        incr i
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
            incr i
        }
    }

    return $constraintDict
}

proc asn1::parse_collection_constraint_before_of {tokensVar indexVar} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    set len [llength $tokens]
    set savedIdx $i
    set constraints [dict create]

    if {$i < $len && [lindex $tokens $i] eq "(" && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "SIZE"} {
        set constraints [asn1::parse_constraint_optional tokens i]
    } elseif {$i < $len && [lindex $tokens $i] eq "SIZE"} {
        set constraints [asn1::parse_bare_size_constraint_optional tokens i]
    } else {
        return $constraints
    }

    if {$i < $len && [lindex $tokens $i] eq "OF"} {
        return $constraints
    }

    set i $savedIdx
    return [dict create]
}

proc asn1::parse_type_name {tokensVar indexVar} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    set len [llength $tokens]

    set typeName [lindex $tokens $i]
    if {$typeName in {"OCTET" "BIT"} && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "STRING"} {
        set typeName "$typeName STRING"
        incr i 2
    } elseif {$typeName eq "OBJECT" && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "IDENTIFIER"} {
        set typeName "OBJECT IDENTIFIER"
        incr i 2
    } elseif {$typeName eq "EMBEDDED" && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "PDV"} {
        set typeName "EMBEDDED PDV"
        incr i 2
    } else {
        incr i
    }

    return $typeName
}

proc asn1::strip_string_literal {value} {
    if {[string length $value] >= 2 && [string index $value 0] eq "\"" && [string index $value end] eq "\""} {
        set inner [string range $value 1 end-1]
        set result ""
        set i 0
        set len [string length $inner]
        while {$i < $len} {
            set ch [string index $inner $i]
            if {$ch eq "\"" && $i + 1 < $len && [string index $inner [expr {$i+1}]] eq "\""} {
                append result "\""
                incr i 2
                continue
            }
            if {$ch eq "\\" && $i + 1 < $len} {
                append result [string index $inner [expr {$i+1}]]
                incr i 2
                continue
            }
            append result $ch
            incr i
        }
        return $result
    }
    return $value
}

proc asn1::decode_binary_string_literal {token} {
    if {![regexp {^'([01[:space:]]*)'B$} $token _ bits]} {
        error "Invalid binary string literal '$token'"
    }
    regsub -all {[[:space:]]} $bits "" bits
    set bitLength [string length $bits]
    set bytes ""
    for {set i 0} {$i < $bitLength} {incr i 8} {
        set chunk [string range $bits $i [expr {$i + 7}]]
        set padded [format %-8s $chunk]
        regsub -all { } $padded 0 padded
        scan $padded %b value
        append bytes [binary format c $value]
    }
    return [list $bytes $bitLength]
}

proc asn1::decode_hex_string_literal {token} {
    if {![regexp {^'([0-9A-Fa-f[:space:]]*)'H$} $token _ hex]} {
        error "Invalid hex string literal '$token'"
    }
    regsub -all {[[:space:]]} $hex "" hex
    if {[expr {[string length $hex] % 2}] == 1} {
        append hex 0
    }
    return [binary decode hex $hex]
}

proc asn1::oid_named_arc_number {name} {
    set arcMap [dict create \
        itu-t 0 \
        ccitt 0 \
        iso 1 \
        joint-iso-itu-t 2 \
        joint-iso-ccitt 2 \
        standard 0 \
        registration-authority 1 \
        member-body 2 \
        identified-organization 3 \
        org 3 \
        dod 6 \
        internet 1 \
        directory 1 \
        mgmt 2 \
        experimental 3 \
        private 4 \
        security 5 \
        snmpV2 6 \
        mail 7 \
        enterprises 1 \
        us 840]
    if {[dict exists $arcMap $name]} {
        return [dict get $arcMap $name]
    }
    return ""
}

proc asn1::parse_oid_value {tokensVar indexVar errorsVar} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    upvar 1 $errorsVar errors
    set len [llength $tokens]
    set arcs {}

    if {$i >= $len || [lindex $tokens $i] ne "\{"} {
        return $arcs
    }
    incr i

    while {$i < $len && [lindex $tokens $i] ne "\}"} {
        set arcToken [lindex $tokens $i]
        if {$arcToken eq ","} {
            incr i
            continue
        }
        incr i

        if {$i < $len && [lindex $tokens $i] eq "("} {
            incr i
            if {$i < $len} {
                lappend arcs [lindex $tokens $i]
                incr i
            } else {
                lappend errors "Missing numeric value for OBJECT IDENTIFIER arc '$arcToken'"
                break
            }
            if {$i < $len && [lindex $tokens $i] eq ")"} {
                incr i
            } else {
                lappend errors "Missing closing parenthesis for OBJECT IDENTIFIER arc '$arcToken'"
                break
            }
            continue
        }

        if {[string is integer -strict $arcToken]} {
            lappend arcs $arcToken
            continue
        }

        set namedArc [asn1::oid_named_arc_number $arcToken]
        if {$namedArc ne ""} {
            lappend arcs $namedArc
        } else {
            lappend errors "Unknown OBJECT IDENTIFIER arc '$arcToken' requires an explicit numeric value"
            lappend arcs $arcToken
        }
    }

    if {$i < $len && [lindex $tokens $i] eq "\}"} {
        incr i
    } else {
        lappend errors "Missing closing brace for OBJECT IDENTIFIER value"
    }

    return $arcs
}

proc asn1::parse_resolve_base_type {moduleAst typeName} {
    set seen [dict create]
    set baseType $typeName
    while {[dict exists $moduleAst types $baseType] && ![dict exists $seen $baseType]} {
        dict set seen $baseType true
        set typeDef [dict get $moduleAst types $baseType]
        if {![dict exists $typeDef type]} {
            break
        }
        set baseType [dict get $typeDef type]
    }
    return $baseType
}

proc asn1::parse_string_value_literal {token baseType errorsVar} {
    upvar 1 $errorsVar errors

    if {[regexp {^'[01[:space:]]*'B$} $token]} {
        set bitValue [asn1::decode_binary_string_literal $token]
        if {$baseType eq "BIT STRING"} {
            return $bitValue
        }
        if {$baseType eq "OCTET STRING"} {
            set bitLength [lindex $bitValue 1]
            if {[expr {$bitLength % 8}] != 0} {
                lappend errors "OCTET STRING binary literal must contain a whole number of octets"
            }
            return [lindex $bitValue 0]
        }
        return $token
    }

    if {[regexp {^'[0-9A-Fa-f[:space:]]*'H$} $token]} {
        set bytes [asn1::decode_hex_string_literal $token]
        if {$baseType eq "BIT STRING"} {
            regsub -all {[[:space:]]} [string range $token 1 end-2] "" hex
            return [list $bytes [expr {[string length $hex] * 4}]]
        }
        if {$baseType eq "OCTET STRING"} {
            return $bytes
        }
        return $token
    }

    return [asn1::strip_string_literal $token]
}

proc asn1::parse_sequence_value {tokensVar indexVar errorsVar} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    upvar 1 $errorsVar errors
    set len [llength $tokens]
    set seqVal [dict create]

    if {$i >= $len || [lindex $tokens $i] ne "\{"} {
        return $seqVal
    }
    incr i

    while {$i < $len && [lindex $tokens $i] ne "\}"} {
        set fieldName [lindex $tokens $i]
        incr i
        if {$i < $len && [lindex $tokens $i] eq ":"} {
            incr i
        }
        if {$i < $len && [lindex $tokens $i] ni {"," "\}"}} {
            dict set seqVal $fieldName [asn1::parse_any_value_literal tokens i errors]
        } else {
            lappend errors "Missing value for field '$fieldName' in value assignment"
            break
        }
        if {$i < $len && [lindex $tokens $i] eq ","} {
            incr i
        }
    }

    if {$i < $len && [lindex $tokens $i] eq "\}"} {
        incr i
    } else {
        lappend errors "Missing closing brace for value assignment"
    }

    return $seqVal
}

proc asn1::parse_any_value_literal {tokensVar indexVar errorsVar} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    upvar 1 $errorsVar errors
    set len [llength $tokens]

    if {$i >= $len} {
        lappend errors "Missing value in value assignment"
        return ""
    }

    if {[lindex $tokens $i] eq "\{"} {
        return [asn1::parse_sequence_value tokens i errors]
    }

    set first [lindex $tokens $i]
    incr i
    if {$i < $len && [lindex $tokens $i] eq ":"} {
        incr i
        return [dict create $first [asn1::parse_any_value_literal tokens i errors]]
    }
    return [asn1::strip_string_literal $first]
}

proc asn1::parse_value_literal {tokensVar indexVar errorsVar moduleAstVar typeName} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    upvar 1 $errorsVar errors
    upvar 1 $moduleAstVar moduleAst
    set len [llength $tokens]

    if {$i >= $len} {
        lappend errors "Missing value for assignment of type '$typeName'"
        return ""
    }

    set baseType [asn1::parse_resolve_base_type $moduleAst $typeName]
    if {[lindex $tokens $i] eq "\{"} {
        if {$baseType eq "OBJECT IDENTIFIER"} {
            return [asn1::parse_oid_value tokens i errors]
        }
        return [asn1::parse_sequence_value tokens i errors]
    }

    set value [asn1::parse_string_value_literal [lindex $tokens $i] $baseType errors]
    incr i
    return $value
}

proc asn1::parse_enumerated_values {tokensVar indexVar errorsVar} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    upvar 1 $errorsVar errors
    set len [llength $tokens]
    set vals [dict create]
    set extVals [dict create]
    set extensible 0
    set inExtensions 0

    if {$i >= $len || [lindex $tokens $i] ne "\{"} {
        lappend errors "Missing opening brace for ENUMERATED"
        return [list $vals $extensible $extVals]
    }
    incr i

    while {$i < $len && [lindex $tokens $i] ne "\}"} {
        if {[lindex $tokens $i] eq "..."} {
            set extensible 1
            set inExtensions 1
            incr i
            if {$i < $len && [lindex $tokens $i] eq ","} {
                incr i
            }
            continue
        }

        set enumName [lindex $tokens $i]
        incr i
        set enumVal ""
        if {$i < $len && [lindex $tokens $i] eq "("} {
            incr i
            if {$i < $len} {
                set enumVal [lindex $tokens $i]
                incr i
            } else {
                lappend errors "Missing value for ENUMERATED item '$enumName'"
                break
            }
            if {$i < $len && [lindex $tokens $i] eq ")"} {
                incr i
            } else {
                lappend errors "Missing closing parenthesis for ENUMERATED item '$enumName'"
                break
            }
        }

        if {$inExtensions} {
            dict set extVals $enumName $enumVal
        } else {
            dict set vals $enumName $enumVal
        }
        if {$i < $len && [lindex $tokens $i] eq ","} {
            incr i
        }
    }

    if {$i < $len && [lindex $tokens $i] eq "\}"} {
        incr i
    } else {
        lappend errors "Missing closing brace for ENUMERATED"
    }

    return [list $vals $extensible $extVals]
}

proc asn1::component_order_has_components_of {order} {
    foreach entry $order {
        if {[lindex $entry 0] eq "componentsOf"} {
            return 1
        }
    }
    return 0
}

proc asn1::maybe_set_component_order {typeInfoVar order extensionOrder} {
    upvar 1 $typeInfoVar typeInfo
    if {[asn1::component_order_has_components_of $order]} {
        dict set typeInfo componentOrder $order
    }
    if {[asn1::component_order_has_components_of $extensionOrder]} {
        dict set typeInfo extensionAdditionOrder $extensionOrder
    }
}

proc asn1::parse_type {tokensVar indexVar errorsVar {moduleAstVar ""} {parentName ""} {fieldName ""}} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    upvar 1 $errorsVar errors
    if {$moduleAstVar ne ""} {
        upvar 1 $moduleAstVar moduleAst
    }
    set len [llength $tokens]

    set typeName [asn1::parse_type_name tokens i]
    set leadingConstraints [dict create]
    if {$typeName in {"SEQUENCE" "SET"}} {
        set leadingConstraints [asn1::parse_collection_constraint_before_of tokens i]
    }

    if {$typeName in {"SEQUENCE" "SET"} && $i < $len && [lindex $tokens $i] eq "OF"} {
        set ofType $typeName
        incr i
        set elemToken [lindex $tokens $i]
        if {$elemToken in {"SEQUENCE" "SET" "CHOICE"} && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "\{"} {
            if {$moduleAstVar eq "" || $parentName eq ""} {
                lappend errors "$ofType OF inline element type requires a parent type name"
                return [dict create type "$ofType OF" elementType $elemToken]
            }
            set elemNamePart $fieldName
            if {$elemNamePart eq ""} {
                set elemNamePart "item"
            }
            set elemType "${parentName}_${elemNamePart}"
            if {$fieldName ne ""} {
                append elemType "_item"
            }
            incr i 2
            lassign [asn1::parse_components tokens i errors moduleAst $elemType] subFields subExtensible subExtensions subOrder subExtensionOrder
            set elemDef [dict create type $elemToken components $subFields]
            if {$subExtensible} {
                dict set elemDef extensible 1
                dict set elemDef extensionAdditions $subExtensions
            }
            asn1::maybe_set_component_order elemDef $subOrder $subExtensionOrder
            dict set moduleAst types $elemType $elemDef
            if {$i < $len && [lindex $tokens $i] eq "\}"} {
                incr i
            } else {
                lappend errors "Missing closing brace for inline $elemToken '$elemType'"
            }
        } else {
            set elemType [asn1::parse_type_name tokens i]
        }
        set typeInfo [dict create type "$ofType OF" elementType $elemType]
    } elseif {$typeName in {"SEQUENCE" "SET" "CHOICE"} && $i < $len && [lindex $tokens $i] eq "\{"} {
        incr i
        if {$moduleAstVar ne "" && $parentName ne "" && $fieldName eq ""} {
            lassign [asn1::parse_components tokens i errors moduleAst $parentName] subFields subExtensible subExtensions subOrder subExtensionOrder
            set typeInfo [dict create type $typeName components $subFields]
            if {$subExtensible} {
                dict set typeInfo extensible 1
                dict set typeInfo extensionAdditions $subExtensions
            }
            asn1::maybe_set_component_order typeInfo $subOrder $subExtensionOrder
            if {$i < $len && [lindex $tokens $i] eq "\}"} {
                incr i
            } else {
                lappend errors "Missing closing brace for $typeName '$parentName'"
            }
        } else {
            if {$moduleAstVar eq "" || $parentName eq "" || $fieldName eq ""} {
                lappend errors "Inline type '$typeName' requires a parent type name and field name"
                return [dict create type $typeName]
            }
            set syntheticName "${parentName}_${fieldName}"
            lassign [asn1::parse_components tokens i errors moduleAst $syntheticName] subFields subExtensible subExtensions subOrder subExtensionOrder
            set syntheticDef [dict create type $typeName components $subFields]
            if {$subExtensible} {
                dict set syntheticDef extensible 1
                dict set syntheticDef extensionAdditions $subExtensions
            }
            asn1::maybe_set_component_order syntheticDef $subOrder $subExtensionOrder
            dict set moduleAst types $syntheticName $syntheticDef
            if {$i < $len && [lindex $tokens $i] eq "\}"} {
                incr i
            } else {
                lappend errors "Missing closing brace for inline $typeName '$syntheticName'"
            }
            set typeInfo [dict create type $syntheticName]
        }
    } elseif {$typeName eq "ENUMERATED" && $i < $len && [lindex $tokens $i] eq "\{"} {
        lassign [asn1::parse_enumerated_values tokens i errors] enumValues enumExtensible enumExtensions
        set typeInfo [dict create type "ENUMERATED" values $enumValues]
        if {$enumExtensible} {
            dict set typeInfo extensible 1
            dict set typeInfo extensionAdditions $enumExtensions
        }
    } else {
        set typeInfo [dict create type $typeName]
    }

    set parsedType [dict get $typeInfo type]
    if {$i < $len && [lindex $tokens $i] eq "\{" && ($parsedType eq "INTEGER" || $parsedType eq "BIT STRING")} {
        set namedValues [asn1::parse_named_number_list tokens i errors]
        if {$parsedType eq "BIT STRING"} {
            dict set typeInfo namedBits $namedValues
        } else {
            dict set typeInfo namedNumbers $namedValues
        }
    }

    set constraints $leadingConstraints
    set trailingConstraints [asn1::parse_constraint_optional tokens i]
    dict for {constraintName constraintValue} $trailingConstraints {
        dict set constraints $constraintName $constraintValue
    }
    if {$constraints ne {}} {
        dict set typeInfo constraints $constraints
    }

    return $typeInfo
}


# Parse the components (fields) inside a SEQUENCE, SET, or CHOICE block.
# Reads tokens from the current index until the closing brace.
proc asn1::parse_components {tokensVar indexVar errorsVar {moduleAstVar ""} {parentName ""}} {
    upvar 1 $tokensVar tokens
    upvar 1 $indexVar i
    upvar 1 $errorsVar errors
    if {$moduleAstVar ne ""} {
        upvar 1 $moduleAstVar moduleAst
    }
    set len [llength $tokens]
    set fields [dict create]
    set extensions [dict create]
    set order {}
    set extensionOrder {}
    set extensible 0
    set inExtensions 0

    while {$i < $len && [lindex $tokens $i] ne "\}"} {
        set current [lindex $tokens $i]

        if {$current eq "..."} {
            set extensible 1
            set inExtensions 1
            incr i
            if {$i < $len && [lindex $tokens $i] eq ","} {
                incr i
            }
            continue
        }

        if {$current eq "\[" && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "\["} {
            set extensible 1
            set inExtensions 1
            incr i 2
            if {$i + 1 < $len && [string is integer -strict [lindex $tokens $i]] && [lindex $tokens [expr {$i+1}]] eq ":"} {
                incr i 2
            }
            continue
        }

        if {$current eq "\]" && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "\]"} {
            incr i 2
            if {$i < $len && [lindex $tokens $i] eq ","} {
                incr i
            }
            continue
        }

        if {$current eq "COMPONENTS" && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "OF"} {
            incr i 2
            if {$i >= $len} {
                lappend errors "Missing type reference after COMPONENTS OF"
                break
            }
            set componentType [asn1::parse_type_name tokens i]
            if {$inExtensions} {
                lappend extensionOrder [list componentsOf $componentType]
            } else {
                lappend order [list componentsOf $componentType]
            }
            if {$i < $len && [lindex $tokens $i] eq ","} {
                incr i
            }
            continue
        }

        set fieldName $current
        incr i

        if {$i >= $len || [lindex $tokens $i] eq "\}"} {
            lappend errors "Unexpected end of component list after field name '$fieldName'"
            break
        }

        set memberTag [asn1::parse_tag_optional tokens i]

        if {$i >= $len || [lindex $tokens $i] eq "\}"} {
            lappend errors "Missing type for field '$fieldName'"
            break
        }

        if {$moduleAstVar ne ""} {
            set fieldInfo [asn1::parse_type tokens i errors moduleAst $parentName $fieldName]
        } else {
            set fieldInfo [asn1::parse_type tokens i errors]
        }
        if {$memberTag ne {}} {
            dict set fieldInfo tag $memberTag
        }

        if {$i < $len && [lindex $tokens $i] eq "OPTIONAL"} {
            dict set fieldInfo optional true
            incr i
        }

        if {$i < $len && [lindex $tokens $i] eq "DEFAULT"} {
            incr i
            if {$i < $len && [lindex $tokens $i] ni {"," "\}" "..."}} {
                dict set fieldInfo default [asn1::strip_string_literal [lindex $tokens $i]]
                incr i
            }
        }

        if {$inExtensions} {
            dict set extensions $fieldName $fieldInfo
            lappend extensionOrder [list field $fieldName]
        } else {
            dict set fields $fieldName $fieldInfo
            lappend order [list field $fieldName]
        }
        if {$i < $len && [lindex $tokens $i] eq ","} {
            incr i
        }
    }

    return [list $fields $extensible $extensions $order $extensionOrder]
}

proc asn1::apply_automatic_tags {moduleAstVar {moduleName ""}} {
    upvar 1 $moduleAstVar moduleAst
    if {![dict exists $moduleAst tagging] || [dict get $moduleAst tagging] ne "AUTOMATIC"} {
        return
    }
    if {$moduleName ne ""} {
        set localAst [dict create $moduleName $moduleAst]
    } else {
        set localAst ""
    }

    foreach typeName [dict keys [dict get $moduleAst types]] {
        set typeDef [dict get $moduleAst types $typeName]
        if {![dict exists $typeDef type] || [dict get $typeDef type] ni {"SEQUENCE" "SET" "CHOICE"}} {
            continue
        }

        set nextTag 0
        foreach componentPair {{components componentOrder} {extensionAdditions extensionAdditionOrder}} {
            lassign $componentPair componentKey orderKey
            if {![dict exists $moduleAst types $typeName $componentKey]} {
                continue
            }
            if {[dict exists $moduleAst types $typeName $orderKey]} {
                foreach entry [dict get $moduleAst types $typeName $orderKey] {
                    if {[lindex $entry 0] eq "componentsOf"} {
                        if {$localAst ne ""} {
                            set refType [lindex $entry 1]
                            if {[catch {set refComps [asn1::ber_resolve_components_of $localAst $moduleName $refType [dict create]]}]} {
                                incr nextTag
                            } else {
                                incr nextTag [dict size $refComps]
                            }
                        } else {
                            incr nextTag
                        }
                        continue
                    }
                    set fieldName [lindex $entry 1]
                    if {![dict exists $moduleAst types $typeName $componentKey $fieldName]} {
                        continue
                    }
                    set fieldDef [dict get $moduleAst types $typeName $componentKey $fieldName]
                    if {![dict exists $fieldDef tag]} {
                        dict set moduleAst types $typeName $componentKey $fieldName tag [dict create class CONTEXT-SPECIFIC number $nextTag]
                    }
                    incr nextTag
                }
                continue
            }

            dict for {fieldName fieldDef} [dict get $moduleAst types $typeName $componentKey] {
                if {![dict exists $fieldDef tag]} {
                    dict set moduleAst types $typeName $componentKey $fieldName tag [dict create class CONTEXT-SPECIFIC number $nextTag]
                }
                incr nextTag
            }
        }
    }
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
            
            set extensibilityImplied 0
            if {$searchIdx + 1 < $len && [lindex $tokens $searchIdx] eq "EXTENSIBILITY" && [lindex $tokens [expr {$searchIdx+1}]] eq "IMPLIED"} {
                set extensibilityImplied 1
                incr searchIdx 2
            }

            if {$searchIdx + 1 < $len && [lindex $tokens $searchIdx] eq "::=" && [lindex $tokens [expr {$searchIdx+1}]] eq "BEGIN"} {
                set moduleAst [dict create tagging $tagging_ imports [dict create] types [dict create] values [dict create]]
                if {$extensibilityImplied} {
                    dict set moduleAst extensibilityImplied 1
                }
                set i [expr {$searchIdx + 2}]

                if {$i < $len && [lindex $tokens $i] eq "EXPORTS"} {
                    incr i
                    set exports {}
                    while {$i < $len && [lindex $tokens $i] ne ";" && [lindex $tokens $i] ne "END"} {
                        set sym [lindex $tokens $i]
                        if {$sym ne ","} {
                            lappend exports $sym
                        }
                        incr i
                    }
                    if {$i < $len && [lindex $tokens $i] eq ";"} {
                        incr i
                    } else {
                        lappend errors "EXPORTS block missing terminating semicolon"
                    }
                    dict set moduleAst exports $exports
                }

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
                        set i $tempIdx
                        set typeInfo [asn1::parse_type tokens i errors moduleAst $ident ""]
                        if {$tagDict ne {}} {
                            dict set typeInfo tag $tagDict
                        }
                        if {$extensibilityImplied && [dict exists $typeInfo type] && [dict get $typeInfo type] in {"SEQUENCE" "SET" "CHOICE" "ENUMERATED"} && ![dict exists $typeInfo extensible]} {
                            dict set typeInfo extensible 1
                        }
                        dict set moduleAst types $ident $typeInfo
                    } else {
                        set typeIdx [expr {$i + 1}]
                        if {$typeIdx < $len} {
                            set valTypeRef [asn1::parse_type_name tokens typeIdx]
                        } else {
                            set valTypeRef ""
                        }

                        if {$valTypeRef ne "" && $typeIdx < $len && [lindex $tokens $typeIdx] eq "::="} {
                            set valName $ident
                            set valAssignIdx [expr {$typeIdx + 1}]
                            set value [asn1::parse_value_literal tokens valAssignIdx errors moduleAst $valTypeRef]
                            dict set moduleAst values $valName [dict create type $valTypeRef value $value]
                            set i $valAssignIdx
                        } else {
                            incr i
                        }
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
                asn1::apply_automatic_tags moduleAst $moduleName
                dict set ast $moduleName $moduleAst
            } else {
                incr i
            }
        } else {
            incr i
        }
    }

    return [asn1::validate_ast [asn1::merge_imports $ast]]
}

proc asn1::assert_parse_invariant {condition message} {
    if {!$condition} {
        error "ASN.1 parser invariant failed: $message"
    }
}

proc asn1::validate_tag_ast {tag path} {
    asn1::assert_parse_invariant [dict exists $tag class] "$path tag missing class"
    asn1::assert_parse_invariant [dict exists $tag number] "$path tag missing number"
    set tagClass [dict get $tag class]
    asn1::assert_parse_invariant [expr {$tagClass in {"UNIVERSAL" "APPLICATION" "CONTEXT-SPECIFIC" "PRIVATE"}}] "$path tag has invalid class '$tagClass'"
    if {[dict exists $tag mode]} {
        set tagMode [dict get $tag mode]
        asn1::assert_parse_invariant [expr {$tagMode in {"IMPLICIT" "EXPLICIT"}}] "$path tag has invalid mode '$tagMode'"
    }
}

proc asn1::validate_component_order {typeDef componentKey orderKey path} {
    if {![dict exists $typeDef $orderKey]} {
        return
    }
    set order [dict get $typeDef $orderKey]
    foreach entry $order {
        set kind [lindex $entry 0]
        switch $kind {
            "field" {
                set fieldName [lindex $entry 1]
                asn1::assert_parse_invariant [expr {$fieldName ne ""}] "$path $orderKey has empty field entry"
                asn1::assert_parse_invariant [dict exists $typeDef $componentKey $fieldName] "$path $orderKey references unknown field '$fieldName'"
            }
            "componentsOf" {
                set refName [lindex $entry 1]
                asn1::assert_parse_invariant [expr {$refName ne ""}] "$path $orderKey has empty COMPONENTS OF reference"
            }
            default {
                asn1::assert_parse_invariant 0 "$path $orderKey has invalid entry kind '$kind'"
            }
        }
    }
}

proc asn1::validate_type_ast {typeDef path} {
    asn1::assert_parse_invariant [dict exists $typeDef type] "$path missing type"
    set typeName [dict get $typeDef type]
    asn1::assert_parse_invariant [expr {$typeName ne ""}] "$path has empty type"

    if {[dict exists $typeDef tag]} {
        asn1::validate_tag_ast [dict get $typeDef tag] $path
    }

    if {$typeName in {"SEQUENCE" "SET" "CHOICE"}} {
        asn1::assert_parse_invariant [dict exists $typeDef components] "$path $typeName missing components"
        dict for {fieldName fieldDef} [dict get $typeDef components] {
            asn1::validate_type_ast $fieldDef "$path.$fieldName"
        }
        asn1::validate_component_order $typeDef components componentOrder $path
        if {[dict exists $typeDef extensionAdditions]} {
            dict for {fieldName fieldDef} [dict get $typeDef extensionAdditions] {
                asn1::validate_type_ast $fieldDef "$path.$fieldName"
            }
            asn1::validate_component_order $typeDef extensionAdditions extensionAdditionOrder $path
        }
    }

    if {$typeName in {"SEQUENCE OF" "SET OF"}} {
        asn1::assert_parse_invariant [dict exists $typeDef elementType] "$path $typeName missing elementType"
        asn1::assert_parse_invariant [expr {[dict get $typeDef elementType] ne ""}] "$path $typeName has empty elementType"
    }

    if {$typeName eq "ENUMERATED"} {
        asn1::assert_parse_invariant [dict exists $typeDef values] "$path ENUMERATED missing values"
    }

    if {[dict exists $typeDef namedBits]} {
        asn1::assert_parse_invariant [expr {$typeName eq "BIT STRING"}] "$path namedBits allowed only on BIT STRING"
    }
    if {[dict exists $typeDef namedNumbers]} {
        asn1::assert_parse_invariant [expr {$typeName eq "INTEGER"}] "$path namedNumbers allowed only on INTEGER"
    }
    if {[dict exists $typeDef constraints]} {
        dict for {constraintName constraintValue} [dict get $typeDef constraints] {
            asn1::assert_parse_invariant [expr {$constraintName in {"SIZE" "RANGE"}}] "$path has unsupported constraint '$constraintName'"
            asn1::assert_parse_invariant [expr {$constraintValue ne ""}] "$path constraint '$constraintName' is empty"
        }
    }
}

proc asn1::validate_ast {ast} {
    dict for {moduleName moduleAst} $ast {
        foreach key {tagging imports types values} {
            asn1::assert_parse_invariant [dict exists $moduleAst $key] "module $moduleName missing $key"
        }
        set tagging [dict get $moduleAst tagging]
        asn1::assert_parse_invariant [expr {$tagging in {"EXPLICIT" "IMPLICIT" "AUTOMATIC"}}] "module $moduleName has invalid tagging '$tagging'"

        if {[dict exists $moduleAst exports]} {
            foreach symbol [dict get $moduleAst exports] {
                asn1::assert_parse_invariant [expr {$symbol ni {"," ";" ""}}] "module $moduleName has invalid export symbol '$symbol'"
            }
        }

        dict for {sourceModule symbols} [dict get $moduleAst imports] {
            asn1::assert_parse_invariant [expr {$sourceModule ne ""}] "module $moduleName has empty import source"
            foreach symbol $symbols {
                asn1::assert_parse_invariant [expr {$symbol ni {"," ";" ""}}] "module $moduleName imports invalid symbol '$symbol'"
            }
        }

        dict for {typeName typeDef} [dict get $moduleAst types] {
            asn1::validate_type_ast $typeDef "$moduleName.$typeName"
        }

        dict for {valueName valueDef} [dict get $moduleAst values] {
            asn1::assert_parse_invariant [dict exists $valueDef type] "value $moduleName.$valueName missing type"
            asn1::assert_parse_invariant [dict exists $valueDef value] "value $moduleName.$valueName missing value"
        }
    }
    return $ast
}

proc asn1::type_reference_names {typeDef} {
    set refs {}
    if {![dict exists $typeDef type]} {
        return $refs
    }

    set typeName [dict get $typeDef type]
    if {$typeName ni [asn1::ber_builtin_types]} {
        lappend refs $typeName
    }

    if {$typeName in {"SEQUENCE" "SET" "CHOICE"}} {
        foreach componentKey {components extensionAdditions} {
            if {![dict exists $typeDef $componentKey]} {
                continue
            }
            dict for {_ componentDef} [dict get $typeDef $componentKey] {
                foreach ref [asn1::type_reference_names $componentDef] {
                    lappend refs $ref
                }
            }
        }
        foreach orderKey {componentOrder extensionAdditionOrder} {
            if {![dict exists $typeDef $orderKey]} {
                continue
            }
            foreach entry [dict get $typeDef $orderKey] {
                if {[lindex $entry 0] eq "componentsOf"} {
                    set refName [lindex $entry 1]
                    if {$refName ni [asn1::ber_builtin_types]} {
                        lappend refs $refName
                    }
                }
            }
        }
    }

    if {$typeName in {"SEQUENCE OF" "SET OF"} && [dict exists $typeDef elementType]} {
        set elemType [dict get $typeDef elementType]
        if {$elemType ni [asn1::ber_builtin_types]} {
            lappend refs $elemType
        }
    }

    return [lsort -unique $refs]
}

proc asn1::mark_origin_module {typeDef originModule} {
    if {![dict exists $typeDef originModule]} {
        dict set typeDef originModule $originModule
    }

    foreach componentKey {components extensionAdditions} {
        if {![dict exists $typeDef $componentKey]} {
            continue
        }
        dict for {fieldName fieldDef} [dict get $typeDef $componentKey] {
            dict set typeDef $componentKey $fieldName [asn1::mark_origin_module $fieldDef $originModule]
        }
    }

    return $typeDef
}

proc asn1::merge_imported_type {astVar targetModule sourceModule typeName seenVar} {
    upvar 1 $astVar ast
    upvar 1 $seenVar seen

    set seenKey "$targetModule\x1f$sourceModule\x1f$typeName"
    if {[dict exists $seen $seenKey]} {
        return 0
    }
    dict set seen $seenKey true

    if {![dict exists $ast $sourceModule types $typeName]} {
        return 0
    }

    set changed 0
    set sourceTypeDef [dict get $ast $sourceModule types $typeName]
    if {![dict exists $ast $targetModule types $typeName]} {
        dict set ast $targetModule types $typeName [asn1::mark_origin_module $sourceTypeDef $sourceModule]
        set changed 1
    }

    foreach refName [asn1::type_reference_names $sourceTypeDef] {
        if {$refName eq $typeName} {
            continue
        }
        if {[dict exists $ast $sourceModule types $refName]} {
            if {[asn1::merge_imported_type ast $targetModule $sourceModule $refName seen]} {
                set changed 1
            }
        }
    }

    return $changed
}

proc asn1::module_add_error {astVar moduleName message} {
    upvar 1 $astVar ast
    if {[dict exists $ast $moduleName errors_]} {
        set errors [dict get $ast $moduleName errors_]
    } else {
        set errors {}
    }
    if {[lsearch -exact $errors $message] == -1} {
        lappend errors $message
        dict set ast $moduleName errors_ $errors
    }
}

proc asn1::type_missing_dependencies {ast moduleName typeName seenVar} {
    upvar 1 $seenVar seen
    if {[dict exists $seen $typeName]} {
        return {}
    }
    dict set seen $typeName true

    if {![dict exists $ast $moduleName types $typeName]} {
        return [list $typeName]
    }

    set missing {}
    set typeDef [dict get $ast $moduleName types $typeName]
    foreach refName [asn1::type_reference_names $typeDef] {
        if {[dict exists $ast $moduleName types $refName]} {
            foreach depName [asn1::type_missing_dependencies $ast $moduleName $refName seen] {
                lappend missing $depName
            }
        } else {
            lappend missing $refName
        }
    }

    return [lsort -unique $missing]
}

proc asn1::annotate_unresolved_imports {astVar} {
    upvar 1 $astVar ast
    dict for {moduleName moduleAst} $ast {
        if {![dict exists $moduleAst imports]} {
            continue
        }

        dict for {sourceModule symbols} [dict get $moduleAst imports] {
            if {![dict exists $ast $sourceModule]} {
                asn1::module_add_error ast $moduleName "Unresolved import source module '$sourceModule' in module '$moduleName'"
                continue
            }

            foreach symbol $symbols {
                if {![dict exists $ast $sourceModule types $symbol] && ![dict exists $ast $sourceModule values $symbol]} {
                    asn1::module_add_error ast $moduleName "Unresolved import symbol '$symbol' from module '$sourceModule' in module '$moduleName'"
                    continue
                }

                if {[dict exists $ast $sourceModule types $symbol]} {
                    set seen [dict create]
                    foreach depName [asn1::type_missing_dependencies $ast $sourceModule $symbol seen] {
                        asn1::module_add_error ast $moduleName "Unresolved type reference '$depName' required by imported type '$symbol' from module '$sourceModule' in module '$moduleName'"
                    }
                }
            }
        }
    }
}

proc asn1::merge_imports {ast} {
    set changed 1
    while {$changed} {
        set changed 0
        dict for {moduleName moduleAst} $ast {
            if {![dict exists $moduleAst imports]} {
                continue
            }
            dict for {sourceModule symbols} [dict get $moduleAst imports] {
                if {![dict exists $ast $sourceModule]} {
                    continue
                }
                foreach symbol $symbols {
                    set seen [dict create]
                    if {[asn1::merge_imported_type ast $moduleName $sourceModule $symbol seen]} {
                        set changed 1
                    }
                    if {[dict exists $ast $sourceModule values $symbol] && ![dict exists $ast $moduleName values $symbol]} {
                        dict set ast $moduleName values $symbol [dict get $ast $sourceModule values $symbol]
                        set changed 1
                    }
                }
            }
        }
    }
    asn1::annotate_unresolved_imports ast
    return $ast
}

proc asn1::parse_file {filepath} {
    set fp [open $filepath r]
    set data [read $fp]
    close $fp
    return [asn1::parse_str $data]
}

proc asn1::parse_files {filepaths} {
    set data ""
    foreach filepath $filepaths {
        set fp [open $filepath r]
        append data [read $fp] "\n"
        close $fp
    }
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

proc asn1::ber_encode_tag {tagClass constructedBit tagNum} {
    if {$tagNum < 31} {
        return [binary format c [expr {$tagClass | $constructedBit | $tagNum}]]
    }
    set bytes [binary format c [expr {$tagClass | $constructedBit | 31}]]
    set temp $tagNum
    set tagBytes {}
    while {$temp > 0} {
        set b [expr {$temp & 0x7F}]
        set temp [expr {$temp >> 7}]
        if {[string length $tagBytes] > 0} {
            set b [expr {$b | 0x80}]
        }
        set tagBytes [binary format c $b]$tagBytes
    }
    return $bytes$tagBytes
}

proc asn1::ber_decode_tag {bytes idxVar classVar consVar numVar} {
    upvar 1 $idxVar idx
    upvar 1 $classVar class
    upvar 1 $consVar cons
    upvar 1 $numVar num

    if {$idx >= [string length $bytes]} {
        error "Truncated BER tag"
    }
    
    binary scan [string index $bytes $idx] c tagByte
    set tagByte [expr {$tagByte & 0xFF}]
    incr idx
    
    set class [expr {$tagByte & 0xC0}]
    set cons [expr {$tagByte & 0x20}]
    set num [expr {$tagByte & 0x1F}]
    
    if {$num == 31} {
        set num 0
        while {1} {
            if {$idx >= [string length $bytes]} {
                error "Truncated BER high-tag-number encoding"
            }
            binary scan [string index $bytes $idx] c b
            set b [expr {$b & 0xFF}]
            incr idx
            set num [expr {($num << 7) | ($b & 0x7F)}]
            if {($b & 0x80) == 0} {
                break
            }
        }
    }
}

proc asn1::ber_encode_tlv {tagClass constructedBit tagNum valueBytes} {
    set tagBytes [asn1::ber_encode_tag $tagClass $constructedBit $tagNum]
    set lenBytes [asn1::ber_encode_length [string length $valueBytes]]
    return ${tagBytes}${lenBytes}${valueBytes}
}

proc asn1::ber_encode_integer_tlv {value} {
    return [asn1::ber_encode_tlv 0x00 0x00 2 [asn1::ber_encode_integer $value]]
}

proc asn1::ber_encode_boolean_tlv {value} {
    return [asn1::ber_encode_tlv 0x00 0x00 1 [binary format c [expr {$value ? 0xFF : 0x00}]]]
}

proc asn1::ber_encode_utf8_string_tlv {value} {
    return [asn1::ber_encode_tlv 0x00 0x00 12 [encoding convertto utf-8 $value]]
}

proc asn1::ber_encode_null_tlv {} {
    return [asn1::ber_encode_tlv 0x00 0x00 5 ""]
}

proc asn1::ber_encode_sequence_tlv {valueBytes} {
    return [asn1::ber_encode_tlv 0x00 0x20 16 $valueBytes]
}

proc asn1::ber_encode_set_tlv {valueBytes} {
    return [asn1::ber_encode_tlv 0x00 0x20 17 $valueBytes]
}

proc asn1::ber_decode_tlv {bytes {idx 0}} {
    set startIdx $idx
    asn1::ber_decode_tag $bytes idx tagClass constructedBit tagNum
    set valueStartIdx $idx
    set len [asn1::ber_decode_length $bytes idx]
    set valueStartIdx $idx
    set valueBytes [asn1::extract_ber_value $bytes idx $len]
    return [dict create \
        class $tagClass \
        constructed $constructedBit \
        number $tagNum \
        length $len \
        headerLength [expr {$valueStartIdx - $startIdx}] \
        value $valueBytes \
        tlv [string range $bytes $startIdx [expr {$idx - 1}]] \
        nextIndex $idx]
}

proc asn1::ber_constructed_bit {constructed} {
    if {$constructed in {0 32}} {
        return $constructed
    }
    return [expr {$constructed ? 0x20 : 0x00}]
}

proc asn1::ber_wrap_context {tagNum valueBytes {constructed 1}} {
    return [asn1::ber_encode_tlv 0x80 [asn1::ber_constructed_bit $constructed] $tagNum $valueBytes]
}

proc asn1::ber_wrap_application {tagNum valueBytes {constructed 1}} {
    return [asn1::ber_encode_tlv 0x40 [asn1::ber_constructed_bit $constructed] $tagNum $valueBytes]
}

proc asn1::ber_wrap_private {tagNum valueBytes {constructed 1}} {
    return [asn1::ber_encode_tlv 0xC0 [asn1::ber_constructed_bit $constructed] $tagNum $valueBytes]
}

proc asn1::ber_read_exact {chan count} {
    set result ""
    while {[string length $result] < $count} {
        set chunk [read $chan [expr {$count - [string length $result]}]]
        if {$chunk eq ""} {
            error "Unexpected EOF while reading BER TLV"
        }
        append result $chunk
    }
    return $result
}

proc asn1::ber_read_tlv {chan} {
    set tagBytes [asn1::ber_read_exact $chan 1]
    binary scan [string index $tagBytes 0] c firstTagByte
    set firstTagByte [expr {$firstTagByte & 0xFF}]

    if {($firstTagByte & 0x1F) == 0x1F} {
        while {1} {
            set b [asn1::ber_read_exact $chan 1]
            append tagBytes $b
            binary scan $b c tagContinuation
            if {(($tagContinuation & 0xFF) & 0x80) == 0} {
                break
            }
        }
    }

    set lenBytes [asn1::ber_read_exact $chan 1]
    binary scan [string index $lenBytes 0] c firstLenByte
    set firstLenByte [expr {$firstLenByte & 0xFF}]
    if {$firstLenByte == 0x80} {
        error "Indefinite-length channel framing is not supported"
    }

    if {$firstLenByte < 0x80} {
        set len $firstLenByte
    } else {
        set lenByteCount [expr {$firstLenByte & 0x7F}]
        if {$lenByteCount == 0} {
            error "Invalid BER length byte"
        }
        set moreLenBytes [asn1::ber_read_exact $chan $lenByteCount]
        append lenBytes $moreLenBytes
        set len 0
        for {set i 0} {$i < $lenByteCount} {incr i} {
            binary scan [string index $moreLenBytes $i] c b
            set len [expr {($len << 8) | ($b & 0xFF)}]
        }
    }

    set valueBytes [asn1::ber_read_exact $chan $len]
    return ${tagBytes}${lenBytes}${valueBytes}
}

proc asn1::ber_read_sequence {chan} {
    set tlv [asn1::ber_read_tlv $chan]
    set idx 0
    asn1::ber_decode_tag $tlv idx tagClass constructedBit tagNum
    if {$tagClass != 0 || $constructedBit != 0x20 || $tagNum != 16} {
        error "Expected top-level BER SEQUENCE but got class $tagClass constructed $constructedBit tag $tagNum"
    }
    return $tlv
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

proc asn1::ber_builtin_types {} {
    return {"INTEGER" "BOOLEAN" "ENUMERATED" "OCTET STRING" "BIT STRING" "NULL" "OBJECT IDENTIFIER" "UTF8String" "NumericString" "PrintableString" "IA5String" "VisibleString" "ANY" "REAL" "RELATIVE-OID" "EXTERNAL" "EMBEDDED PDV" "UTCTime" "GeneralizedTime" "SEQUENCE" "SET" "SEQUENCE OF" "SET OF" "CHOICE"}
}

proc asn1::ber_encode_oid_subidentifier {val} {
    if {$val < 0} {
        error "OBJECT IDENTIFIER arcs must be non-negative"
    }
    if {$val == 0} {
        return [binary format c 0]
    }
    set bytes ""
    set temp $val
    while {$temp > 0} {
        set b [expr {$temp & 0x7F}]
        set temp [expr {$temp >> 7}]
        if {[string length $bytes] > 0} {
            set b [expr {$b | 0x80}]
        }
        set bytes [binary format c $b]$bytes
    }
    return $bytes
}

proc asn1::ber_encode_oid {value} {
    if {[llength $value] < 2} {
        error "OBJECT IDENTIFIER requires at least two arcs"
    }
    set first [lindex $value 0]
    set second [lindex $value 1]
    if {$first < 0 || $first > 2} {
        error "OBJECT IDENTIFIER first arc must be 0, 1, or 2"
    }
    if {$second < 0 || ($first < 2 && $second > 39)} {
        error "OBJECT IDENTIFIER second arc is out of range"
    }

    set bytes [asn1::ber_encode_oid_subidentifier [expr {$first * 40 + $second}]]
    foreach arc [lrange $value 2 end] {
        append bytes [asn1::ber_encode_oid_subidentifier $arc]
    }
    return $bytes
}

proc asn1::ber_encode_bit_string {value} {
    if {[llength $value] != 2} {
        error "BIT STRING value must be a two-item list: bytes bitLength"
    }
    set bitBytes [lindex $value 0]
    set bitLength [lindex $value 1]
    if {$bitLength < 0} {
        error "BIT STRING bit length must be non-negative"
    }
    set byteLength [string length $bitBytes]
    if {$bitLength > $byteLength * 8} {
        error "BIT STRING bit length exceeds supplied bytes"
    }
    set unusedBits [expr {$byteLength * 8 - $bitLength}]
    if {$byteLength == 0} {
        if {$bitLength != 0} {
            error "BIT STRING with no bytes must have bit length 0"
        }
        set unusedBits 0
    } elseif {$unusedBits < 0 || $unusedBits > 7} {
        error "BIT STRING unused bit count must be between 0 and 7"
    }
    if {$unusedBits > 0 && $byteLength > 0} {
        binary scan [string index $bitBytes end] c lastByte
        set lastByte [expr {$lastByte & 0xFF}]
        set unusedMask [expr {(1 << $unusedBits) - 1}]
        if {($lastByte & $unusedMask) != 0} {
            error "BIT STRING unused bits must be zero"
        }
    }
    return [binary format c $unusedBits]$bitBytes
}

proc asn1::ber_decode_bit_string {valBytes} {
    if {[string length $valBytes] == 0} {
        error "BIT STRING value is missing unused-bit count"
    }
    binary scan [string index $valBytes 0] c unusedBits
    set unusedBits [expr {$unusedBits & 0xFF}]
    if {$unusedBits > 7} {
        error "BIT STRING unused bit count must be between 0 and 7"
    }
    set bitBytes [string range $valBytes 1 end]
    set byteLength [string length $bitBytes]
    if {$byteLength == 0 && $unusedBits != 0} {
        error "BIT STRING with no bytes must have unused bit count 0"
    }
    if {$unusedBits > 0 && $byteLength > 0} {
        binary scan [string index $bitBytes end] c lastByte
        set lastByte [expr {$lastByte & 0xFF}]
        set unusedMask [expr {(1 << $unusedBits) - 1}]
        if {($lastByte & $unusedMask) != 0} {
            error "BIT STRING unused bits must be zero"
        }
    }
    set bitLength [expr {$byteLength * 8 - $unusedBits}]
    return [list $bitBytes $bitLength]
}

proc asn1::ber_encode {ast moduleName typeName value} {
    set typeDef [dict get $ast $moduleName types $typeName]
    return [asn1::ber_encode_type $ast $moduleName $typeDef $value]
}

proc asn1::ber_encode_value {ast moduleName valueName} {
    set valDef [dict get $ast $moduleName values $valueName]
    set valType [dict get $valDef type]
    set rawVal [dict get $valDef value]

    # Resolve the base type to convert value literals correctly
    set resolvedType $valType
    if {[dict exists $ast $moduleName types $valType]} {
        set tDef [dict get $ast $moduleName types $valType]
        set resolvedType [dict get $tDef type]
        while {$resolvedType ni [asn1::ber_builtin_types] && [dict exists $ast $moduleName types $resolvedType]} {
            set tDef [dict get $ast $moduleName types $resolvedType]
            set resolvedType [dict get $tDef type]
        }
    }

    # Convert ASN.1 boolean literals to Tcl values
    set val [asn1::convert_value_literal $resolvedType $rawVal]

    # For SEQUENCE/SET, resolve the type definition to get component info,
    # then use ber_encode with the type name
    if {$resolvedType in {"SEQUENCE" "SET"}} {
        # Resolve boolean fields inside the sequence value
        if {[dict exists $ast $moduleName types $valType]} {
            set seqDef [dict get $ast $moduleName types $valType]
        } else {
            set seqDef [dict create type $valType]
        }
        set resolvedVal [asn1::resolve_seq_value $ast $moduleName $seqDef $val]
        return [asn1::ber_encode $ast $moduleName $valType $resolvedVal]
    }

    # For simple types, encode using the type name if it exists in types,
    # otherwise build a typeDef and encode directly
    if {[dict exists $ast $moduleName types $valType]} {
        return [asn1::ber_encode $ast $moduleName $valType $val]
    } else {
        set typeDef [dict create type $valType]
        return [asn1::ber_encode_type $ast $moduleName $typeDef $val]
    }
}

proc asn1::convert_value_literal {baseType rawVal} {
    switch $baseType {
        "BOOLEAN" {
            if {$rawVal eq "TRUE"} { return 1 }
            if {$rawVal eq "FALSE"} { return 0 }
            return $rawVal
        }
        default {
            return $rawVal
        }
    }
}

proc asn1::ber_resolve_base_type {ast moduleName typeDef} {
    set moduleName [asn1::ber_effective_module $moduleName $typeDef]
    set baseType [dict get $typeDef type]
    while {$baseType ni [asn1::ber_builtin_types] && [asn1::ber_type_exists $ast $moduleName $baseType]} {
        set typeDef [asn1::ber_lookup_type_def $ast $moduleName $baseType]
        set moduleName [asn1::ber_effective_module $moduleName $typeDef]
        set baseType [dict get $typeDef type]
    }
    return $baseType
}

proc asn1::ber_effective_module {moduleName typeDef} {
    if {[dict exists $typeDef originModule]} {
        return [dict get $typeDef originModule]
    }
    return $moduleName
}

proc asn1::ber_type_exists {ast moduleName typeName} {
    return [dict exists $ast $moduleName types $typeName]
}

proc asn1::ber_lookup_type_def {ast moduleName typeName} {
    if {[dict exists $ast $moduleName types $typeName]} {
        return [dict get $ast $moduleName types $typeName]
    }
    error "Type '$typeName' not found in module '$moduleName'"
}

proc asn1::enumerated_value_to_integer {typeDef value} {
    if {[string is integer -strict $value]} {
        return $value
    }

    set nextValue 0
    foreach valueKey {values extensionAdditions} {
        if {![dict exists $typeDef $valueKey]} {
            continue
        }
        dict for {enumName enumValue} [dict get $typeDef $valueKey] {
            if {$enumValue eq ""} {
                set enumValue $nextValue
            }
            if {$enumName eq $value} {
                return $enumValue
            }
            set nextValue [expr {$enumValue + 1}]
        }
    }

    error "Unknown ENUMERATED symbol '$value'"
}

proc asn1::ber_validate_character_string {baseType value} {
    foreach ch [split $value ""] {
        scan $ch %c code
        switch $baseType {
            "IA5String" {
                if {$code < 0 || $code > 127} {
                    error "IA5String value contains invalid characters"
                }
            }
            "VisibleString" {
                if {$code < 32 || $code > 126} {
                    error "VisibleString value contains invalid characters"
                }
            }
        }
    }

    switch $baseType {
        "NumericString" {
            if {![regexp {^[0-9 ]*$} $value]} {
                error "NumericString value contains invalid characters"
            }
        }
        "PrintableString" {
            if {![regexp {^[A-Za-z0-9 '()+,\-./:=?]*$} $value]} {
                error "PrintableString value contains invalid characters"
            }
        }
    }
}

proc asn1::ber_decode_string_value {valBytes tagCons} {
    if {$tagCons != 32} {
        return $valBytes
    }

    set result ""
    set subIdx 0
    while {$subIdx < [string length $valBytes]} {
        asn1::ber_decode_tag $valBytes subIdx _ _ _
        set chunkLen [asn1::ber_decode_length $valBytes subIdx]
        append result [asn1::extract_ber_value $valBytes subIdx $chunkLen]
    }
    return $result
}

proc asn1::resolve_seq_value {ast moduleName seqDef val} {
    # Resolve the actual SEQUENCE/SET type definition
    set moduleName [asn1::ber_effective_module $moduleName $seqDef]
    set baseType [dict get $seqDef type]
    while {$baseType ni {"SEQUENCE" "SET"} && [dict exists $ast $moduleName types $baseType]} {
        set seqDef [dict get $ast $moduleName types $baseType]
        set moduleName [asn1::ber_effective_module $moduleName $seqDef]
        set baseType [dict get $seqDef type]
    }
    if {![dict exists $seqDef components]} {
        return $val
    }
    set comps [asn1::ber_all_components $seqDef $ast $moduleName]
    set result [dict create]
    dict for {fName fVal} $val {
        if {[dict exists $comps $fName]} {
            set fDef [dict get $comps $fName]
            set fType [dict get $fDef type]
            # Resolve the field's base type
            set fBaseType $fType
            while {$fBaseType ni [asn1::ber_builtin_types] && [dict exists $ast $moduleName types $fBaseType]} {
                set tDef [dict get $ast $moduleName types $fBaseType]
                set fBaseType [dict get $tDef type]
            }
            dict set result $fName [asn1::convert_value_literal $fBaseType $fVal]
        } else {
            dict set result $fName $fVal
        }
    }
    return $result
}

proc asn1::ber_constraint_matches {actual constraint} {
    if {[llength $constraint] == 1} {
        return [expr {$actual == [lindex $constraint 0]}]
    }
    if {[llength $constraint] == 2} {
        set min [lindex $constraint 0]
        set max [lindex $constraint 1]
        return [expr {$actual >= $min && $actual <= $max}]
    }
    foreach item $constraint {
        if {$item eq "|"} {
            continue
        }
        if {$actual == $item} {
            return 1
        }
    }
    return 0
}

proc asn1::ber_size_for_constraint {baseType value {encodingPhase 0}} {
    switch $baseType {
        "OCTET STRING" {
            if {$encodingPhase} {
                return [string length [encoding convertto utf-8 $value]]
            }
            return [string length $value]
        }
        "BIT STRING" {
            return [lindex $value 1]
        }
        "UTF8String" - "NumericString" - "PrintableString" - "IA5String" - "VisibleString" {
            return [string length $value]
        }
        "SEQUENCE OF" - "SET OF" - "OBJECT IDENTIFIER" {
            return [llength $value]
        }
        "SEQUENCE" - "SET" {
            return [expr {[llength [dict keys $value]]}]
        }
        default {
            return [string length $value]
        }
    }
}

proc asn1::ber_check_constraints {typeDef baseType value {encodingPhase 0}} {
    if {![dict exists $typeDef constraints]} {
        return
    }

    dict for {constraintName constraintValue} [dict get $typeDef constraints] {
        switch $constraintName {
            "RANGE" {
                if {![asn1::ber_constraint_matches $value $constraintValue]} {
                    error "RANGE constraint failed for $baseType: value $value not in $constraintValue"
                }
            }
            "SIZE" {
                set actualSize [asn1::ber_size_for_constraint $baseType $value $encodingPhase]
                if {![asn1::ber_constraint_matches $actualSize $constraintValue]} {
                    error "SIZE constraint failed for $baseType: size $actualSize not in $constraintValue"
                }
            }
        }
    }
}

proc asn1::ber_encode_type {ast moduleName typeDef value} {
    set moduleName [asn1::ber_effective_module $moduleName $typeDef]
    set baseType [dict get $typeDef type]

    set hasTag [dict exists $typeDef tag]
    if {$hasTag} {
        set tagDict [dict get $typeDef tag]
        if {[dict exists $tagDict mode]} {
            set tagMode [dict get $tagDict mode]
        } else {
            set tagMode [dict get $ast $moduleName tagging]
        }
        set tagClassStr [dict get $tagDict class]
        set tagNum [dict get $tagDict number]
        
        switch $tagClassStr {
            "UNIVERSAL" { set tagClass 0x00 }
            "APPLICATION" { set tagClass 0x40 }
            "CONTEXT-SPECIFIC" { set tagClass 0x80 }
            "PRIVATE" { set tagClass 0xC0 }
        }

        set innerDef $typeDef
        dict unset innerDef tag
        set innerBase [asn1::ber_resolve_base_type $ast $moduleName $innerDef]

        if {$tagMode eq "EXPLICIT" || $innerBase in {"CHOICE" "ANY"}} {
            set innerBytes [asn1::ber_encode_type $ast $moduleName $innerDef $value]
            
            set tagBytes [asn1::ber_encode_tag $tagClass 0x20 $tagNum]
            set lenBytes [asn1::ber_encode_length [string length $innerBytes]]
            return ${tagBytes}${lenBytes}${innerBytes}
        } else {
            set innerBytes [asn1::ber_encode_type $ast $moduleName $innerDef $value]
            
            # Since innerBytes contains the encoded inner tag, we must read past it
            # to replace it with our implicit tag.
            set tagIdx 0
            asn1::ber_decode_tag $innerBytes tagIdx _ innerCons _
            
            set constructedBit $innerCons
            set tagBytes [asn1::ber_encode_tag $tagClass $constructedBit $tagNum]
            return ${tagBytes}[string range $innerBytes $tagIdx end]
        }
    }

    if {$baseType ni [asn1::ber_builtin_types]} {
        set aliasDef [asn1::ber_lookup_type_def $ast $moduleName $baseType]
        return [asn1::ber_encode_type $ast $moduleName $aliasDef $value]
    }

    if {$baseType eq "ANY"} {
        return $value
    }

    asn1::ber_check_constraints $typeDef $baseType $value 1

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
        "ENUMERATED" {
            set tagNum 10
            set valBytes [asn1::ber_encode_integer [asn1::enumerated_value_to_integer $typeDef $value]]
        }
        "OCTET STRING" {
            set tagNum 4
            set valBytes [encoding convertto utf-8 $value]
        }
        "BIT STRING" {
            set tagNum 3
            set valBytes [asn1::ber_encode_bit_string $value]
        }
        "NULL" {
            set tagNum 5
            if {$value ne ""} {
                error "NULL value must be empty"
            }
            set valBytes ""
        }
        "OBJECT IDENTIFIER" {
            set tagNum 6
            set valBytes [asn1::ber_encode_oid $value]
        }
        "UTF8String" {
            set tagNum 12
            set valBytes [encoding convertto utf-8 $value]
        }
        "NumericString" {
            set tagNum 18
            asn1::ber_validate_character_string $baseType $value
            set valBytes [encoding convertto utf-8 $value]
        }
        "PrintableString" {
            set tagNum 19
            asn1::ber_validate_character_string $baseType $value
            set valBytes [encoding convertto utf-8 $value]
        }
        "IA5String" {
            set tagNum 22
            asn1::ber_validate_character_string $baseType $value
            set valBytes [encoding convertto utf-8 $value]
        }
        "VisibleString" {
            set tagNum 26
            asn1::ber_validate_character_string $baseType $value
            set valBytes [encoding convertto utf-8 $value]
        }
        "SEQUENCE" - "SET" {
            set tagNum [expr {$baseType eq "SEQUENCE" ? 16 : 17}]
            set valBytes ""
            set comps [asn1::ber_all_components $typeDef $ast $moduleName]
            dict for {fieldName fieldDef} $comps {
                if {[dict exists $value $fieldName]} {
                    set fieldValue [dict get $value $fieldName]
                    if {[dict exists $fieldDef default]} {
                        set fieldBaseType [asn1::ber_resolve_base_type $ast $moduleName $fieldDef]
                        set defaultValue [asn1::convert_value_literal $fieldBaseType [dict get $fieldDef default]]
                        if {$fieldValue eq $defaultValue} {
                            continue
                        }
                    }
                    append valBytes [asn1::ber_encode_type $ast $moduleName $fieldDef $fieldValue]
                }
            }
        }
        "SEQUENCE OF" - "SET OF" {
            set tagNum [expr {$baseType eq "SEQUENCE OF" ? 16 : 17}]
            set valBytes ""
            set elemDef [dict create type [dict get $typeDef elementType]]
            foreach elem $value {
                append valBytes [asn1::ber_encode_type $ast $moduleName $elemDef $elem]
            }
        }
        "CHOICE" {
            set keys [dict keys $value]
            if {[llength $keys] != 1} { error "CHOICE value must have exactly one key" }
            set chosenField [lindex $keys 0]
            if {$chosenField eq "_extension" && [asn1::ber_type_is_extensible $typeDef]} {
                return [dict get $value $chosenField]
            }
            set fieldDef [dict get [asn1::ber_all_components $typeDef $ast $moduleName] $chosenField]
            return [asn1::ber_encode_type $ast $moduleName $fieldDef [dict get $value $chosenField]]
        }
        default {
            error "BER encode not implemented for $baseType"
        }
    }

    set tagBytes [asn1::ber_encode_tag 0x00 [expr {$baseType in {"SEQUENCE" "SET" "SEQUENCE OF" "SET OF"} ? 0x20 : 0x00}] $tagNum]
    set lenBytes [asn1::ber_encode_length [string length $valBytes]]
    return ${tagBytes}${lenBytes}${valBytes}
}

# --- BER Decoder ---

proc asn1::format_tag {tag} {
    if {[llength $tag] != 3} {
        return $tag
    }
    lassign $tag class cons num
    set classStr ""
    switch $class {
        0 { set classStr "UNIVERSAL" }
        64 { set classStr "APPLICATION" }
        128 { set classStr "CONTEXT-SPECIFIC" }
        192 { set classStr "PRIVATE" }
    }
    set consStr [expr {$cons == 32 ? "CONSTRUCTED" : "PRIMITIVE"}]
    return "$classStr $consStr $num"
}

proc asn1::format_tags {tags} {
    set res {}
    foreach tag $tags {
        lappend res "\[[asn1::format_tag $tag]\]"
    }
    return [join $res " or "]
}


proc asn1::ber_decode_length {bytes idxVar} {
    upvar 1 $idxVar idx
    if {$idx >= [string length $bytes]} {
        error "Truncated BER length"
    }
    binary scan [string index $bytes $idx] c b
    set b [expr {$b & 0xFF}]
    incr idx
    if {$b == 128} {
        return -1 ;# Indefinite length
    }
    if {$b < 128} {
        return $b
    }
    set numBytes [expr {$b & 0x7F}]
    if {$numBytes == 0} {
        error "Invalid BER length byte"
    }
    if {$idx + $numBytes > [string length $bytes]} {
        error "Truncated BER long-form length"
    }
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

proc asn1::ber_decode_oid_subidentifier {bytes idxVar} {
    upvar 1 $idxVar idx
    set val 0
    while {$idx < [string length $bytes]} {
        binary scan [string index $bytes $idx] c b
        set b [expr {$b & 0xFF}]
        incr idx
        set val [expr {($val << 7) | ($b & 0x7F)}]
        if {($b & 0x80) == 0} {
            return $val
        }
    }
    error "Truncated OBJECT IDENTIFIER subidentifier"
}

proc asn1::ber_decode_oid {bytes} {
    if {[string length $bytes] == 0} {
        error "OBJECT IDENTIFIER value is empty"
    }
    set idx 0
    set firstSubid [asn1::ber_decode_oid_subidentifier $bytes idx]
    if {$firstSubid < 40} {
        set arcs [list 0 $firstSubid]
    } elseif {$firstSubid < 80} {
        set arcs [list 1 [expr {$firstSubid - 40}]]
    } else {
        set arcs [list 2 [expr {$firstSubid - 80}]]
    }
    while {$idx < [string length $bytes]} {
        lappend arcs [asn1::ber_decode_oid_subidentifier $bytes idx]
    }
    return $arcs
}

proc asn1::get_expected_tag {ast moduleName typeDef} {
    set moduleName [asn1::ber_effective_module $moduleName $typeDef]
    if {[dict exists $typeDef tag]} {
        set tagDict [dict get $typeDef tag]
        if {[dict exists $tagDict mode]} {
            set tagMode [dict get $tagDict mode]
        } else {
            set tagMode [dict get $ast $moduleName tagging]
        }
        set tagClassStr [dict get $tagDict class]
        set tagNum [dict get $tagDict number]
        switch $tagClassStr {
            "UNIVERSAL" { set tagClass 0 }
            "APPLICATION" { set tagClass 64 }
            "CONTEXT-SPECIFIC" { set tagClass 128 }
            "PRIVATE" { set tagClass 192 }
        }
        
        set innerDef $typeDef
        dict unset innerDef tag
        
        set effectiveMode $tagMode
        set tempBase [asn1::ber_resolve_base_type $ast $moduleName $innerDef]
        if {$tempBase in {"CHOICE" "ANY"}} {
            set effectiveMode "EXPLICIT"
        }
        
        if {$effectiveMode eq "EXPLICIT"} {
            return [list [list $tagClass 32 $tagNum]]
        } else {
            set innerTags [asn1::get_expected_tag $ast $moduleName $innerDef]
            set res {}
            foreach itag $innerTags {
                set constructedBit [lindex $itag 1]
                lappend res [list $tagClass $constructedBit $tagNum]
            }
            return $res
        }
    }

    set baseType [dict get $typeDef type]
    if {$baseType ni [asn1::ber_builtin_types]} {
        set aliasDef [asn1::ber_lookup_type_def $ast $moduleName $baseType]
        return [asn1::get_expected_tag $ast $moduleName $aliasDef]
    }

    switch $baseType {
        "INTEGER" { return [list [list 0 0 2]] }
        "BOOLEAN" { return [list [list 0 0 1]] }
        "ENUMERATED" { return [list [list 0 0 10]] }
        "OCTET STRING" { return [list [list 0 0 4] [list 0 32 4]] }
        "BIT STRING" { return [list [list 0 0 3] [list 0 32 3]] }
        "NULL" { return [list [list 0 0 5]] }
        "OBJECT IDENTIFIER" { return [list [list 0 0 6]] }
        "EXTERNAL" { return [list [list 0 32 8]] }
        "REAL" { return [list [list 0 0 9]] }
        "EMBEDDED PDV" { return [list [list 0 32 11]] }
        "RELATIVE-OID" { return [list [list 0 0 13]] }
        "UTF8String" { return [list [list 0 0 12] [list 0 32 12]] }
        "NumericString" { return [list [list 0 0 18] [list 0 32 18]] }
        "PrintableString" { return [list [list 0 0 19] [list 0 32 19]] }
        "IA5String" { return [list [list 0 0 22] [list 0 32 22]] }
        "UTCTime" { return [list [list 0 0 23] [list 0 32 23]] }
        "GeneralizedTime" { return [list [list 0 0 24] [list 0 32 24]] }
        "VisibleString" { return [list [list 0 0 26] [list 0 32 26]] }
        "ANY" { return {} }
        "SEQUENCE" { return [list [list 0 32 16]] }
        "SET" { return [list [list 0 32 17]] }
        "SEQUENCE OF" { return [list [list 0 32 16]] }
        "SET OF" { return [list [list 0 32 17]] }
        "CHOICE" {
            set tags {}
            set comps [asn1::ber_all_components $typeDef $ast $moduleName]
            dict for {fieldName fieldDef} $comps {
                foreach t [asn1::get_expected_tag $ast $moduleName $fieldDef] { lappend tags $t }
            }
            return $tags
        }
        default {
            error "BER tag lookup not implemented for $baseType"
        }
    }
}

proc asn1::ber_decode {ast moduleName typeName bytes} {
    set typeDef [dict get $ast $moduleName types $typeName]
    set idx 0
    set val [asn1::ber_decode_type $ast $moduleName $typeDef $bytes idx]
    set remainder [string range $bytes $idx end]
    return [dict create value $val remainder $remainder]
}

proc asn1::ber_peek_tag {bytes idx} {
    set probeIdx $idx
    asn1::ber_decode_tag $bytes probeIdx tagClass constructedBit tagNum
    return [list $tagClass $constructedBit $tagNum]
}

proc asn1::ber_type_accepts_any_tag {ast moduleName typeDef} {
    return [expr {[asn1::ber_resolve_base_type $ast $moduleName $typeDef] eq "ANY"}]
}

proc asn1::ber_tag_matches_type {ast moduleName typeDef parsedTag} {
    set expectedTags [asn1::get_expected_tag $ast $moduleName $typeDef]
    if {$expectedTags eq {}} {
        return [asn1::ber_type_accepts_any_tag $ast $moduleName $typeDef]
    }
    return [expr {[lsearch -exact $expectedTags $parsedTag] != -1}]
}

proc asn1::ber_component_default_value {ast moduleName fieldDef} {
    set fieldBaseType [asn1::ber_resolve_base_type $ast $moduleName $fieldDef]
    return [asn1::convert_value_literal $fieldBaseType [dict get $fieldDef default]]
}

proc asn1::ber_type_is_extensible {typeDef} {
    return [expr {[dict exists $typeDef extensible] && [dict get $typeDef extensible]}]
}

proc asn1::ber_resolve_components_of {ast moduleName refType seen} {
    set key "$moduleName\x1f$refType"
    if {[dict exists $seen $key]} {
        error "Circular COMPONENTS OF reference involving '$refType'"
    }
    dict set seen $key true

    set refDef [asn1::ber_lookup_type_def $ast $moduleName $refType]
    set refModule [asn1::ber_effective_module $moduleName $refDef]
    set baseType [dict get $refDef type]
    while {$baseType ni {"SEQUENCE" "SET"} && $baseType ni [asn1::ber_builtin_types] && [asn1::ber_type_exists $ast $refModule $baseType]} {
        set refDef [asn1::ber_lookup_type_def $ast $refModule $baseType]
        set refModule [asn1::ber_effective_module $refModule $refDef]
        set baseType [dict get $refDef type]
    }
    if {$baseType ni {"SEQUENCE" "SET"}} {
        error "COMPONENTS OF '$refType' must reference a SEQUENCE or SET type"
    }

    return [asn1::ber_all_components $refDef $ast $refModule $seen]
}

proc asn1::ber_add_ordered_components {resultVar typeDef componentKey orderKey ast moduleName seen} {
    upvar 1 $resultVar result

    if {[dict exists $typeDef $orderKey] && $ast ne "" && $moduleName ne ""} {
        foreach entry [dict get $typeDef $orderKey] {
            set kind [lindex $entry 0]
            if {$kind eq "field"} {
                set fieldName [lindex $entry 1]
                if {[dict exists $typeDef $componentKey $fieldName]} {
                    dict set result $fieldName [dict get $typeDef $componentKey $fieldName]
                }
            } elseif {$kind eq "componentsOf"} {
                set refType [lindex $entry 1]
                set refComps [asn1::ber_resolve_components_of $ast $moduleName $refType $seen]
                dict for {fieldName fieldDef} $refComps {
                    dict set result $fieldName $fieldDef
                }
            }
        }
    } elseif {[dict exists $typeDef $componentKey]} {
        dict for {fieldName fieldDef} [dict get $typeDef $componentKey] {
            dict set result $fieldName $fieldDef
        }
    }
}

proc asn1::ber_all_components {typeDef {ast ""} {moduleName ""} {seen {}}} {
    set comps [dict create]
    asn1::ber_add_ordered_components comps $typeDef components componentOrder $ast $moduleName $seen
    asn1::ber_add_ordered_components comps $typeDef extensionAdditions extensionAdditionOrder $ast $moduleName $seen
    return $comps
}

proc asn1::ber_set_find_component {ast moduleName comps seenFields parsedTag} {
    set anyCandidate ""
    dict for {fieldName fieldDef} $comps {
        if {[dict exists $seenFields $fieldName]} {
            continue
        }
        if {[asn1::ber_type_accepts_any_tag $ast $moduleName $fieldDef]} {
            if {$anyCandidate eq ""} {
                set anyCandidate $fieldName
            }
            continue
        }
        if {[asn1::ber_tag_matches_type $ast $moduleName $fieldDef $parsedTag]} {
            return $fieldName
        }
    }
    return $anyCandidate
}

proc asn1::ber_set_tag_is_duplicate {ast moduleName comps seenFields parsedTag} {
    dict for {fieldName fieldDef} $comps {
        if {![dict exists $seenFields $fieldName]} {
            continue
        }
        if {[asn1::ber_type_accepts_any_tag $ast $moduleName $fieldDef]} {
            continue
        }
        if {[asn1::ber_tag_matches_type $ast $moduleName $fieldDef $parsedTag]} {
            return 1
        }
    }
    return 0
}

proc asn1::ber_skip_value {bytes idxVar} {
    upvar 1 $idxVar idx
    set startIdx $idx
    asn1::ber_decode_tag $bytes idx _ _ _
    set len [asn1::ber_decode_length $bytes idx]
    if {$len == -1} {
        while {1} {
            if {$idx + 1 >= [string length $bytes]} {
                error "Truncated BER indefinite-length value"
            }
            binary scan [string index $bytes $idx] c b1
            binary scan [string index $bytes [expr {$idx+1}]] c b2
            if {($b1 & 0xFF) == 0 && ($b2 & 0xFF) == 0} {
                incr idx 2
                break
            }
            asn1::ber_skip_value $bytes idx
        }
    } else {
        if {$idx + $len > [string length $bytes]} {
            error "Truncated BER value"
        }
        incr idx $len
    }
    if {$idx <= $startIdx} {
        error "BER skip did not advance"
    }
}

proc asn1::extract_ber_value {bytes idxVar len} {
    upvar 1 $idxVar idx
    if {$len >= 0} {
        if {$idx + $len > [string length $bytes]} {
            error "Truncated BER value"
        }
        set valBytes [string range $bytes $idx [expr {$idx + $len - 1}]]
        incr idx $len
        return $valBytes
    } else {
        set startIdx $idx
        while {1} {
            if {$idx + 1 >= [string length $bytes]} {
                error "Truncated BER indefinite-length value"
            }
            binary scan [string index $bytes $idx] c b1
            binary scan [string index $bytes [expr {$idx+1}]] c b2
            if {($b1 & 0xFF) == 0 && ($b2 & 0xFF) == 0} {
                set valBytes [string range $bytes $startIdx [expr {$idx - 1}]]
                incr idx 2 ;# Skip EOC
                return $valBytes
            }
            asn1::ber_skip_value $bytes idx
        }
    }
}

proc asn1::ber_skip_unknown_extension {bytes idxVar limit} {
    upvar 1 $idxVar idx
    set startIdx $idx
    asn1::ber_skip_value $bytes idx
    if {$idx > $limit} {
        error "Unknown extension field exceeds enclosing BER value"
    }
    return [string range $bytes $startIdx [expr {$idx - 1}]]
}

proc asn1::ber_decode_type {ast moduleName typeDef bytes idxVar} {
    upvar 1 $idxVar idx
    set moduleName [asn1::ber_effective_module $moduleName $typeDef]

    if {[dict exists $typeDef tag]} {
        set tagDict [dict get $typeDef tag]
        if {[dict exists $tagDict mode]} {
            set tagMode [dict get $tagDict mode]
        } else {
            set tagMode [dict get $ast $moduleName tagging]
        }
        
        asn1::ber_decode_tag $bytes idx tagClass tagCons tagNum
        set parsedTag [list $tagClass $tagCons $tagNum]
        
        set expectedTags [asn1::get_expected_tag $ast $moduleName $typeDef]
        if {[lsearch -exact $expectedTags $parsedTag] == -1} {
            set errBaseType [dict get $typeDef type]
            error "Expected tag(s) [asn1::format_tags $expectedTags] (for type $errBaseType) but got tag [asn1::format_tag $parsedTag]"
        }
        
        set len [asn1::ber_decode_length $bytes idx]
        set valBytes [asn1::extract_ber_value $bytes idx $len]
        
        set innerDef $typeDef
        dict unset innerDef tag
        
        set effectiveMode $tagMode
        set tempBase [asn1::ber_resolve_base_type $ast $moduleName $innerDef]
        if {$tempBase in {"CHOICE" "ANY"}} {
            set effectiveMode "EXPLICIT"
        }
        
        if {$effectiveMode eq "EXPLICIT"} {
            set subIdx 0
            return [asn1::ber_decode_type $ast $moduleName $innerDef $valBytes subIdx]
        } else {
            set innerTags [asn1::get_expected_tag $ast $moduleName $innerDef]
            set fakeTag [lindex $innerTags 0]
            set fakeTagByte [asn1::ber_encode_tag [lindex $fakeTag 0] [lindex $fakeTag 1] [lindex $fakeTag 2]]
            set fakeLenBytes [asn1::ber_encode_length [string length $valBytes]]
            set fakeBytes ${fakeTagByte}${fakeLenBytes}${valBytes}
            set subIdx 0
            return [asn1::ber_decode_type $ast $moduleName $innerDef $fakeBytes subIdx]
        }
    }

    set baseType [dict get $typeDef type]
    if {$baseType ni [asn1::ber_builtin_types]} {
        set aliasDef [asn1::ber_lookup_type_def $ast $moduleName $baseType]
        return [asn1::ber_decode_type $ast $moduleName $aliasDef $bytes idx]
    }

    if {$baseType eq "ANY"} {
        set tlv [asn1::ber_decode_tlv $bytes $idx]
        set idx [dict get $tlv nextIndex]
        return [dict get $tlv tlv]
    }

    set startIdx $idx
    asn1::ber_decode_tag $bytes idx tagClass tagCons tagNum
    set parsedTag [list $tagClass $tagCons $tagNum]
    
    if {$baseType eq "CHOICE"} {
        set comps [asn1::ber_all_components $typeDef $ast $moduleName]
        dict for {fieldName fieldDef} $comps {
            set expectedTags [asn1::get_expected_tag $ast $moduleName $fieldDef]
            if {[lsearch -exact $expectedTags $parsedTag] != -1} {
                set idx $startIdx ;# Backtrack
                return [dict create $fieldName [asn1::ber_decode_type $ast $moduleName $fieldDef $bytes idx]]
            }
        }
        if {[asn1::ber_type_is_extensible $typeDef]} {
            set idx $startIdx
            set tlv [asn1::ber_skip_unknown_extension $bytes idx [string length $bytes]]
            return [dict create _extension $tlv]
        }
        error "No matching tag [asn1::format_tag $parsedTag] in CHOICE"
    } else {
        set expectedTags [asn1::get_expected_tag $ast $moduleName $typeDef]
        if {$expectedTags ne {} && [lsearch -exact $expectedTags $parsedTag] == -1} {
            error "Expected tag(s) [asn1::format_tags $expectedTags] (for type $baseType) but got tag [asn1::format_tag $parsedTag]"
        }
    }

    set len [asn1::ber_decode_length $bytes idx]
    set valBytes [asn1::extract_ber_value $bytes idx $len]

    switch $baseType {
        "INTEGER" { set decodedValue [asn1::ber_decode_integer $valBytes] }
        "ENUMERATED" { set decodedValue [asn1::ber_decode_integer $valBytes] }
        "BOOLEAN" {
            binary scan [string index $valBytes 0] c b
            set decodedValue [expr {($b & 0xFF) != 0}]
        }
        "OCTET STRING" {
            # Handle constructed OCTET STRING (tag has constructed bit set)
            if {$tagCons == 32} {
                set result ""
                set subIdx 0
                while {$subIdx < [string length $valBytes]} {
                    asn1::ber_decode_tag $valBytes subIdx _ _ _
                    set chunkLen [asn1::ber_decode_length $valBytes subIdx]
                    set chunk [asn1::extract_ber_value $valBytes subIdx $chunkLen]
                    append result $chunk
                }
                set decodedValue $result
            } else {
                set decodedValue $valBytes
            }
        }
        "BIT STRING" {
            set decodedValue [asn1::ber_decode_bit_string $valBytes]
        }
        "NULL" {
            if {[string length $valBytes] != 0} {
                error "NULL value must have zero length"
            }
            set decodedValue ""
        }
        "OBJECT IDENTIFIER" { set decodedValue [asn1::ber_decode_oid $valBytes] }
        "UTF8String" {
            set decodedValue [encoding convertfrom utf-8 [asn1::ber_decode_string_value $valBytes $tagCons]]
        }
        "NumericString" - "PrintableString" - "IA5String" - "VisibleString" {
            set decodedValue [encoding convertfrom utf-8 [asn1::ber_decode_string_value $valBytes $tagCons]]
            asn1::ber_validate_character_string $baseType $decodedValue
        }
        "SEQUENCE" {
            set result [dict create]
            set subIdx 0
            set comps [asn1::ber_all_components $typeDef $ast $moduleName]
            set valLen [string length $valBytes]
            dict for {fieldName fieldDef} $comps {
                if {$subIdx >= $valLen} {
                    if {[dict exists $fieldDef optional] && [dict get $fieldDef optional]} { continue }
                    if {[dict exists $fieldDef default]} {
                        dict set result $fieldName [asn1::ber_component_default_value $ast $moduleName $fieldDef]
                        continue
                    }
                    error "Missing mandatory field $fieldName"
                }

                set nextTag [asn1::ber_peek_tag $valBytes $subIdx]
                if {![asn1::ber_tag_matches_type $ast $moduleName $fieldDef $nextTag]} {
                    if {[dict exists $fieldDef optional] && [dict get $fieldDef optional]} {
                        continue
                    }
                    if {[dict exists $fieldDef default]} {
                        dict set result $fieldName [asn1::ber_component_default_value $ast $moduleName $fieldDef]
                        continue
                    }
                    error "Expected field $fieldName tag [asn1::format_tags [asn1::get_expected_tag $ast $moduleName $fieldDef]] but got tag [asn1::format_tag $nextTag]"
                }

                set fieldVal [asn1::ber_decode_type $ast $moduleName $fieldDef $valBytes subIdx]
                dict set result $fieldName $fieldVal
            }
            if {[asn1::ber_type_is_extensible $typeDef]} {
                while {$subIdx < $valLen} {
                    asn1::ber_skip_unknown_extension $valBytes subIdx $valLen
                }
            }
            set decodedValue $result
        }
        "SET" {
            set decodedFields [dict create]
            set seenFields [dict create]
            set subIdx 0
            set comps [asn1::ber_all_components $typeDef $ast $moduleName]
            set valLen [string length $valBytes]

            while {$subIdx < $valLen} {
                set nextTag [asn1::ber_peek_tag $valBytes $subIdx]
                set fieldName [asn1::ber_set_find_component $ast $moduleName $comps $seenFields $nextTag]
                if {$fieldName eq ""} {
                    if {[asn1::ber_set_tag_is_duplicate $ast $moduleName $comps $seenFields $nextTag]} {
                        error "Duplicate SET field tag [asn1::format_tag $nextTag]"
                    }
                    if {[asn1::ber_type_is_extensible $typeDef]} {
                        asn1::ber_skip_unknown_extension $valBytes subIdx $valLen
                        continue
                    }
                    error "Unexpected SET field tag [asn1::format_tag $nextTag]"
                }

                set fieldDef [dict get $comps $fieldName]
                set fieldVal [asn1::ber_decode_type $ast $moduleName $fieldDef $valBytes subIdx]
                dict set decodedFields $fieldName $fieldVal
                dict set seenFields $fieldName true
            }

            set result [dict create]
            dict for {fieldName fieldDef} $comps {
                if {[dict exists $decodedFields $fieldName]} {
                    dict set result $fieldName [dict get $decodedFields $fieldName]
                } elseif {[dict exists $fieldDef optional] && [dict get $fieldDef optional]} {
                    continue
                } elseif {[dict exists $fieldDef default]} {
                    dict set result $fieldName [asn1::ber_component_default_value $ast $moduleName $fieldDef]
                } else {
                    error "Missing mandatory field $fieldName"
                }
            }
            set decodedValue $result
        }
        "SEQUENCE OF" - "SET OF" {
            set result {}
            set subIdx 0
            set elemDef [dict create type [dict get $typeDef elementType]]
            set valLen [string length $valBytes]
            while {$subIdx < $valLen} {
                lappend result [asn1::ber_decode_type $ast $moduleName $elemDef $valBytes subIdx]
            }
            set decodedValue $result
        }
        default {
            error "BER decode not implemented for $baseType"
        }
    }

    asn1::ber_check_constraints $typeDef $baseType $decodedValue 0
    return $decodedValue
}
