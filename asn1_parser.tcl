package provide asn1 1.0

namespace eval asn1 {
    
    # Tokenize the ASN.1 text into a list of tokens
    proc tokenize {text} {
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
            if {[string first $ch "{}()\[\],;"] != -1} {
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
    proc parse_tag_optional {tokensVar indexVar} {
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
    proc parse_components {tokensVar indexVar errorsVar} {
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
            set memberTag [parse_tag_optional tokens i]
            
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
    proc parse {tokens} {
        set ast [dict create]
        set len [llength $tokens]
        set i 0
        
        while {$i < $len} {
            set token [lindex $tokens $i]
            
            # Look for Module Definition: ModuleName DEFINITIONS ... ::= BEGIN
            if {$i + 1 < $len && [lindex $tokens [expr {$i+1}]] eq "DEFINITIONS"} {
                set moduleName $token
                set tagging "EXPLICIT" ;# default default
                set errors {}
                
                set searchIdx [expr {$i + 2}]
                # Check for optional tagging environment
                if {$searchIdx < $len && [lindex $tokens $searchIdx] in {"EXPLICIT" "IMPLICIT" "AUTOMATIC"}} {
                    if {$searchIdx + 1 < $len && [lindex $tokens [expr {$searchIdx+1}]] eq "TAGS"} {
                        set tagging [lindex $tokens $searchIdx]
                        incr searchIdx 2
                    }
                }
                
                if {$searchIdx + 1 < $len && [lindex $tokens $searchIdx] eq "::=" && [lindex $tokens [expr {$searchIdx+1}]] eq "BEGIN"} {
                    set moduleAst [dict create tagging $tagging imports [dict create] types [dict create] values [dict create]]
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
                            set tagDict [parse_tag_optional tokens tempIdx]
                            set rhsToken [lindex $tokens $tempIdx]
                            
                            if {$rhsToken eq "SEQUENCE" && $tempIdx + 1 < $len && [lindex $tokens [expr {$tempIdx+1}]] eq "\{"} {
                                # Parse SEQUENCE
                                set i [expr {$tempIdx + 2}]
                                set fields [parse_components tokens i errors]
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
                                set fields [parse_components tokens i errors]
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
                        dict set moduleAst errors $errors
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
    
    proc parse_file {filepath} {
        set fp [open $filepath r]
        set data [read $fp]
        close $fp
        set tokens [tokenize $data]
        return [parse $tokens]
    }
}
