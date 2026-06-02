package provide asn1 0.2.0

namespace eval asn1 {
    namespace export parse_file parse_files parse_str ber_encode ber_decode ber_encode_value
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
    set extensible 0
    set inExtensions 0

    while {$i < $len && [lindex $tokens $i] ne "\}"} {
        # Skip extension markers
        if {[lindex $tokens $i] eq "..."} {
            set extensible 1
            set inExtensions 1
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

        # Handle OCTET STRING, BIT STRING, OBJECT IDENTIFIER
        if {$fieldType in {"OCTET" "BIT"} && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "STRING"} {
            set fieldType "$fieldType STRING"
            incr i
        } elseif {$fieldType eq "OBJECT" && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "IDENTIFIER"} {
            set fieldType "OBJECT IDENTIFIER"
            incr i
        }

        # Handle SEQUENCE OF / SET OF
        if {$fieldType in {"SEQUENCE" "SET"} && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "OF"} {
            set ofType $fieldType
            incr i 2 ;# skip past "OF"
            # Read the element type
            set elemType [lindex $tokens $i]
            if {$elemType in {"OCTET" "BIT"} && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "STRING"} {
                set elemType "$elemType STRING"
                incr i
            } elseif {$elemType eq "OBJECT" && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "IDENTIFIER"} {
                set elemType "OBJECT IDENTIFIER"
                incr i
            }
            set fieldInfo [dict create type "$ofType OF" elementType $elemType]
            if {$memberTag ne {}} {
                dict set fieldInfo tag $memberTag
            }
            incr i
        } elseif {$fieldType in {"SEQUENCE" "SET" "CHOICE"} && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "\{"} {
            # Inline nested complex type — parse recursively and register as synthetic type
            set syntheticName "${parentName}_${fieldName}"
            incr i 2 ;# skip past opening brace
            if {$fieldType eq "CHOICE" || $fieldType eq "SEQUENCE" || $fieldType eq "SET"} {
                lassign [asn1::parse_components tokens i errors moduleAst $syntheticName] subFields subExtensible subExtensions
                if {$moduleAstVar ne ""} {
                    dict set moduleAst types $syntheticName type $fieldType
                    dict set moduleAst types $syntheticName components $subFields
                    if {$subExtensible} {
                        dict set moduleAst types $syntheticName extensible 1
                        dict set moduleAst types $syntheticName extensionAdditions $subExtensions
                    }
                }
            }
            if {$i < $len && [lindex $tokens $i] eq "\}"} {
                incr i ;# skip closing brace
            }
            set fieldInfo [dict create type $syntheticName]
            if {$memberTag ne {}} {
                dict set fieldInfo tag $memberTag
            }
        } else {
            set fieldInfo [dict create type $fieldType]
            if {$memberTag ne {}} {
                dict set fieldInfo tag $memberTag
            }
            incr i
        }

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

        if {$inExtensions} {
            dict set extensions $fieldName $fieldInfo
        } else {
            dict set fields $fieldName $fieldInfo
        }
        if {$i < $len && [lindex $tokens $i] eq ","} {
            incr i
        }
    }

    return [list $fields $extensible $extensions]
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

                        if {$rhsToken eq "SEQUENCE" && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "OF"} {
                            # Parse SEQUENCE OF
                            set i [expr {$tempIdx + 2}]
                            set elemType [lindex $tokens $i]
                            if {$elemType in {"OCTET" "BIT"} && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "STRING"} {
                                set elemType "$elemType STRING"
                                incr i
                            } elseif {$elemType eq "OBJECT" && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "IDENTIFIER"} {
                                set elemType "OBJECT IDENTIFIER"
                                incr i
                            }
                            incr i
                            dict set moduleAst types $ident type "SEQUENCE OF"
                            dict set moduleAst types $ident elementType $elemType
                            if {$tagDict ne {}} {
                                dict set moduleAst types $ident tag $tagDict
                            }
                        } elseif {$rhsToken eq "SET" && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "OF"} {
                            # Parse SET OF
                            set i [expr {$tempIdx + 2}]
                            set elemType [lindex $tokens $i]
                            if {$elemType in {"OCTET" "BIT"} && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "STRING"} {
                                set elemType "$elemType STRING"
                                incr i
                            } elseif {$elemType eq "OBJECT" && $i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "IDENTIFIER"} {
                                set elemType "OBJECT IDENTIFIER"
                                incr i
                            }
                            incr i
                            dict set moduleAst types $ident type "SET OF"
                            dict set moduleAst types $ident elementType $elemType
                            if {$tagDict ne {}} {
                                dict set moduleAst types $ident tag $tagDict
                            }
                        } elseif {$rhsToken eq "SEQUENCE" && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "\{"} {
                            # Parse SEQUENCE
                            set i [expr {$tempIdx + 2}]
                            lassign [asn1::parse_components tokens i errors moduleAst $ident] fields extensible extensions
                            dict set moduleAst types $ident type "SEQUENCE"
                            if {$tagDict ne {}} {
                                dict set moduleAst types $ident tag $tagDict
                            }
                            dict set moduleAst types $ident components $fields
                            if {$extensible} {
                                dict set moduleAst types $ident extensible 1
                                dict set moduleAst types $ident extensionAdditions $extensions
                            } elseif {$extensibilityImplied} {
                                dict set moduleAst types $ident extensible 1
                            }
                            if {$i < $len && [lindex $tokens $i] eq "\}"} {
                                incr i ;# skip closing brace
                            } else {
                                lappend errors "Missing closing brace for SEQUENCE '$ident'"
                            }
                        } elseif {$rhsToken eq "CHOICE" && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "\{"} {
                            # Parse CHOICE
                            set i [expr {$tempIdx + 2}]
                            lassign [asn1::parse_components tokens i errors moduleAst $ident] fields extensible extensions
                            dict set moduleAst types $ident type "CHOICE"
                            if {$tagDict ne {}} {
                                dict set moduleAst types $ident tag $tagDict
                            }
                            dict set moduleAst types $ident components $fields
                            if {$extensible} {
                                dict set moduleAst types $ident extensible 1
                                dict set moduleAst types $ident extensionAdditions $extensions
                            } elseif {$extensibilityImplied} {
                                dict set moduleAst types $ident extensible 1
                            }
                            if {$i < $len && [lindex $tokens $i] eq "\}"} {
                                incr i ;# skip closing brace
                            } else {
                                lappend errors "Missing closing brace for CHOICE '$ident'"
                            }
                        } elseif {$rhsToken eq "SET" && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "\{"} {
                            # Parse SET
                            set i [expr {$tempIdx + 2}]
                            lassign [asn1::parse_components tokens i errors moduleAst $ident] fields extensible extensions
                            dict set moduleAst types $ident type "SET"
                            if {$tagDict ne {}} {
                                dict set moduleAst types $ident tag $tagDict
                            }
                            dict set moduleAst types $ident components $fields
                            if {$extensible} {
                                dict set moduleAst types $ident extensible 1
                                dict set moduleAst types $ident extensionAdditions $extensions
                            } elseif {$extensibilityImplied} {
                                dict set moduleAst types $ident extensible 1
                            }
                            if {$i < $len && [lindex $tokens $i] eq "\}"} {
                                incr i ;# skip closing brace
                            } else {
                                lappend errors "Missing closing brace for SET '$ident'"
                            }
                        } elseif {$rhsToken eq "ENUMERATED" && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "\{"} {
                            # Parse ENUMERATED
                            set i [expr {$tempIdx + 2}]
                            set vals [dict create]
                            set extVals [dict create]
                            set extensible 0
                            set inExtensions 0
                            
                            while {$i < $len && [lindex $tokens $i] ne "\}"} {
                                if {[lindex $tokens $i] eq "..."} {
                                    set extensible 1
                                    set inExtensions 1
                                    incr i
                                    if {$i < $len && [lindex $tokens $i] eq ","} { incr i }
                                    continue
                                }
                                set enumName [lindex $tokens $i]
                                incr i
                                set enumVal ""
                                if {$i < $len && [lindex $tokens $i] eq "("} {
                                    incr i
                                    set enumVal [lindex $tokens $i]
                                    incr i ;# closing )
                                    if {$i < $len && [lindex $tokens $i] eq ")"} { incr i }
                                }
                                if {$inExtensions} {
                                    dict set extVals $enumName $enumVal
                                } else {
                                    dict set vals $enumName $enumVal
                                }
                                if {$i < $len && [lindex $tokens $i] eq ","} { incr i }
                            }
                            dict set moduleAst types $ident type "ENUMERATED"
                            if {$tagDict ne {}} { dict set moduleAst types $ident tag $tagDict }
                            dict set moduleAst types $ident values $vals
                            if {$extensible} {
                                dict set moduleAst types $ident extensible 1
                                dict set moduleAst types $ident extensionAdditions $extVals
                            } elseif {$extensibilityImplied} {
                                dict set moduleAst types $ident extensible 1
                            }
                            if {$i < $len && [lindex $tokens $i] eq "\}"} {
                                incr i
                            } else {
                                lappend errors "Missing closing brace for ENUMERATED '$ident'"
                            }
                        } else {
                            # Simple type assignment
                            set fieldType $rhsToken
                            if {$fieldType in {"OCTET" "BIT"} && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "STRING"} {
                                set fieldType "$fieldType STRING"
                                set i [expr {$tempIdx + 2}]
                            } elseif {$fieldType eq "OBJECT" && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "IDENTIFIER"} {
                                set fieldType "OBJECT IDENTIFIER"
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
                        # Check for value assignment: valueName TYPE ::= value
                        # or: valueName OCTET STRING ::= value
                        set isValueAssign 0
                        set valTypeRef ""
                        set valAssignIdx 0

                        if {$i + 2 < $len && [lindex $tokens [expr {$i+2}]] eq "::="} {
                            # Pattern: valueName TYPE ::= value
                            set valTypeRef [lindex $tokens [expr {$i+1}]]
                            set valAssignIdx [expr {$i + 3}]
                            set isValueAssign 1
                        } elseif {$i + 3 < $len && [lindex $tokens [expr {$i+1}]] in {"OCTET" "BIT"} && [lindex $tokens [expr {$i+2}]] eq "STRING" && [lindex $tokens [expr {$i+3}]] eq "::="} {
                            # Pattern: valueName OCTET STRING ::= value
                            set valTypeRef "[lindex $tokens [expr {$i+1}]] STRING"
                            set valAssignIdx [expr {$i + 4}]
                            set isValueAssign 1
                        }

                        if {$isValueAssign && $valAssignIdx < $len} {
                            set valName $ident
                            # Parse the value literal
                            set valTok [lindex $tokens $valAssignIdx]
                            if {$valTok eq "\{"} {
                                # Sequence/Set value parsing
                                incr valAssignIdx
                                set seqVal [dict create]
                                while {$valAssignIdx < $len && [lindex $tokens $valAssignIdx] ne "\}"} {
                                    set fName [lindex $tokens $valAssignIdx]
                                    incr valAssignIdx
                                    if {$valAssignIdx < $len && [lindex $tokens $valAssignIdx] ni {"," "\}"}} {
                                        set fVal [lindex $tokens $valAssignIdx]
                                        dict set seqVal $fName $fVal
                                        incr valAssignIdx
                                    }
                                    if {$valAssignIdx < $len && [lindex $tokens $valAssignIdx] eq ","} {
                                        incr valAssignIdx
                                    }
                                }
                                if {$valAssignIdx < $len && [lindex $tokens $valAssignIdx] eq "\}"} {
                                    incr valAssignIdx
                                }
                                dict set moduleAst values $valName [dict create type $valTypeRef value $seqVal]
                                set i $valAssignIdx
                            } else {
                                # Simple literal value (integer, boolean, string, reference)
                                set litVal $valTok
                                # Strip quotes from string literals
                                if {[string index $litVal 0] eq "\"" && [string index $litVal end] eq "\""} {
                                    set litVal [string range $litVal 1 end-1]
                                }
                                dict set moduleAst values $valName [dict create type $valTypeRef value $litVal]
                                set i [expr {$valAssignIdx + 1}]
                            }
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
                dict set ast $moduleName $moduleAst
            } else {
                incr i
            }
        } else {
            incr i
        }
    }

    return [asn1::merge_imports $ast]
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
                    if {[dict exists $ast $sourceModule types $symbol] && ![dict exists $ast $moduleName types $symbol]} {
                        dict set ast $moduleName types $symbol [dict get $ast $sourceModule types $symbol]
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
    
    binary scan [string index $bytes $idx] c tagByte
    set tagByte [expr {$tagByte & 0xFF}]
    incr idx
    
    set class [expr {$tagByte & 0xC0}]
    set cons [expr {$tagByte & 0x20}]
    set num [expr {$tagByte & 0x1F}]
    
    if {$num == 31} {
        set num 0
        while {1} {
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
    return {"INTEGER" "BOOLEAN" "ENUMERATED" "OCTET STRING" "OBJECT IDENTIFIER" "SEQUENCE" "SET" "SEQUENCE OF" "SET OF" "CHOICE"}
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

proc asn1::resolve_seq_value {ast moduleName seqDef val} {
    # Resolve the actual SEQUENCE/SET type definition
    set baseType [dict get $seqDef type]
    while {$baseType ni {"SEQUENCE" "SET"} && [dict exists $ast $moduleName types $baseType]} {
        set seqDef [dict get $ast $moduleName types $baseType]
        set baseType [dict get $seqDef type]
    }
    if {![dict exists $seqDef components]} {
        return $val
    }
    set comps [dict get $seqDef components]
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

proc asn1::ber_encode_type {ast moduleName typeDef value} {
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
        
        if {$tagMode eq "EXPLICIT"} {
            set innerDef $typeDef
            dict unset innerDef tag
            set innerBytes [asn1::ber_encode_type $ast $moduleName $innerDef $value]
            
            set tagBytes [asn1::ber_encode_tag $tagClass 0x20 $tagNum]
            set lenBytes [asn1::ber_encode_length [string length $innerBytes]]
            return ${tagBytes}${lenBytes}${innerBytes}
        } else {
            set innerDef $typeDef
            dict unset innerDef tag
            
            # If IMPLICIT on CHOICE, ASN.1 standard dictates it acts as EXPLICIT
            set tempBase [dict get $innerDef type]
            while {$tempBase ni [asn1::ber_builtin_types]} {
                set tempDef [dict get $ast $moduleName types $tempBase]
                set tempBase [dict get $tempDef type]
            }
            if {$tempBase eq "CHOICE"} {
                set innerBytes [asn1::ber_encode_type $ast $moduleName $innerDef $value]
                set tagBytes [asn1::ber_encode_tag $tagClass 0x20 $tagNum]
                set lenBytes [asn1::ber_encode_length [string length $innerBytes]]
                return ${tagBytes}${lenBytes}${innerBytes}
            }

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
        set aliasDef [dict get $ast $moduleName types $baseType]
        return [asn1::ber_encode_type $ast $moduleName $aliasDef $value]
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
        "ENUMERATED" {
            set tagNum 10
            set valBytes [asn1::ber_encode_integer $value]
        }
        "OCTET STRING" {
            set tagNum 4
            set valBytes [encoding convertto utf-8 $value]
        }
        "OBJECT IDENTIFIER" {
            set tagNum 6
            set valBytes [asn1::ber_encode_oid $value]
        }
        "SEQUENCE" - "SET" {
            set tagNum [expr {$baseType eq "SEQUENCE" ? 16 : 17}]
            set valBytes ""
            set comps [dict get $typeDef components]
            dict for {fieldName fieldDef} $comps {
                if {[dict exists $value $fieldName]} {
                    append valBytes [asn1::ber_encode_type $ast $moduleName $fieldDef [dict get $value $fieldName]]
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
            set fieldDef [dict get [dict get $typeDef components] $chosenField]
            return [asn1::ber_encode_type $ast $moduleName $fieldDef [dict get $value $chosenField]]
        }
    }

    set tagBytes [asn1::ber_encode_tag 0x00 [expr {$baseType in {"SEQUENCE" "SET" "SEQUENCE OF" "SET OF"} ? 0x20 : 0x00}] $tagNum]
    set lenBytes [asn1::ber_encode_length [string length $valBytes]]
    return ${tagBytes}${lenBytes}${valBytes}
}

# --- BER Decoder ---

proc asn1::ber_decode_length {bytes idxVar} {
    upvar 1 $idxVar idx
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
        if {$effectiveMode eq "IMPLICIT"} {
            set tempBase [dict get $innerDef type]
            while {$tempBase ni [asn1::ber_builtin_types]} {
                set tempDef [dict get $ast $moduleName types $tempBase]
                set tempBase [dict get $tempDef type]
            }
            if {$tempBase eq "CHOICE"} {
                set effectiveMode "EXPLICIT"
            }
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
        set aliasDef [dict get $ast $moduleName types $baseType]
        return [asn1::get_expected_tag $ast $moduleName $aliasDef]
    }

    switch $baseType {
        "INTEGER" { return [list [list 0 0 2]] }
        "BOOLEAN" { return [list [list 0 0 1]] }
        "ENUMERATED" { return [list [list 0 0 10]] }
        "OCTET STRING" { return [list [list 0 0 4] [list 0 32 4]] }
        "OBJECT IDENTIFIER" { return [list [list 0 0 6]] }
        "SEQUENCE" { return [list [list 0 32 16]] }
        "SET" { return [list [list 0 32 17]] }
        "SEQUENCE OF" { return [list [list 0 32 16]] }
        "SET OF" { return [list [list 0 32 17]] }
        "CHOICE" {
            set tags {}
            set comps [dict get $typeDef components]
            dict for {fieldName fieldDef} $comps {
                foreach t [asn1::get_expected_tag $ast $moduleName $fieldDef] { lappend tags $t }
            }
            return $tags
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

proc asn1::ber_skip_value {bytes idxVar} {
    upvar 1 $idxVar idx
    asn1::ber_decode_tag $bytes idx _ _ _
    set len [asn1::ber_decode_length $bytes idx]
    if {$len == -1} {
        while {1} {
            binary scan [string index $bytes $idx] c b1
            binary scan [string index $bytes [expr {$idx+1}]] c b2
            if {($b1 & 0xFF) == 0 && ($b2 & 0xFF) == 0} {
                incr idx 2
                break
            }
            asn1::ber_skip_value $bytes idx
        }
    } else {
        incr idx $len
    }
}

proc asn1::extract_ber_value {bytes idxVar len} {
    upvar 1 $idxVar idx
    if {$len >= 0} {
        set valBytes [string range $bytes $idx [expr {$idx + $len - 1}]]
        incr idx $len
        return $valBytes
    } else {
        set startIdx $idx
        while {1} {
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

proc asn1::ber_decode_type {ast moduleName typeDef bytes idxVar} {
    upvar 1 $idxVar idx

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
            error "Expected tag $expectedTags but got $parsedTag"
        }
        
        set len [asn1::ber_decode_length $bytes idx]
        set valBytes [asn1::extract_ber_value $bytes idx $len]
        
        set innerDef $typeDef
        dict unset innerDef tag
        
        set effectiveMode $tagMode
        if {$effectiveMode eq "IMPLICIT"} {
            set tempBase [dict get $innerDef type]
            while {$tempBase ni [asn1::ber_builtin_types]} {
                set tempDef [dict get $ast $moduleName types $tempBase]
                set tempBase [dict get $tempDef type]
            }
            if {$tempBase eq "CHOICE"} {
                set effectiveMode "EXPLICIT"
            }
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
        set aliasDef [dict get $ast $moduleName types $baseType]
        return [asn1::ber_decode_type $ast $moduleName $aliasDef $bytes idx]
    }

    set startIdx $idx
    asn1::ber_decode_tag $bytes idx tagClass tagCons tagNum
    set parsedTag [list $tagClass $tagCons $tagNum]
    
    if {$baseType eq "CHOICE"} {
        set comps [dict get $typeDef components]
        dict for {fieldName fieldDef} $comps {
            set expectedTags [asn1::get_expected_tag $ast $moduleName $fieldDef]
            if {[lsearch -exact $expectedTags $parsedTag] != -1} {
                set idx $startIdx ;# Backtrack
                return [dict create $fieldName [asn1::ber_decode_type $ast $moduleName $fieldDef $bytes idx]]
            }
        }
        error "No matching tag $parsedTag in CHOICE"
    }

    set len [asn1::ber_decode_length $bytes idx]
    set valBytes [asn1::extract_ber_value $bytes idx $len]

    switch $baseType {
        "INTEGER" { return [asn1::ber_decode_integer $valBytes] }
        "ENUMERATED" { return [asn1::ber_decode_integer $valBytes] }
        "BOOLEAN" {
            binary scan [string index $valBytes 0] c b
            return [expr {($b & 0xFF) != 0}]
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
                return $result
            }
            return $valBytes
        }
        "OBJECT IDENTIFIER" { return [asn1::ber_decode_oid $valBytes] }
        "SEQUENCE" - "SET" {
            set result [dict create]
            set subIdx 0
            set comps [dict get $typeDef components]
            set valLen [string length $valBytes]
            dict for {fieldName fieldDef} $comps {
                if {$subIdx >= $valLen} {
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
            if {[dict exists $typeDef extensible] && [dict get $typeDef extensible]} {
                while {$subIdx < $valLen} {
                    asn1::ber_skip_value $valBytes subIdx
                }
            }
            return $result
        }
        "SEQUENCE OF" - "SET OF" {
            set result {}
            set subIdx 0
            set elemDef [dict create type [dict get $typeDef elementType]]
            set valLen [string length $valBytes]
            while {$subIdx < $valLen} {
                lappend result [asn1::ber_decode_type $ast $moduleName $elemDef $valBytes subIdx]
            }
            return $result
        }
    }
}
