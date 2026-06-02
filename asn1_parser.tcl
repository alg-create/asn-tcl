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
            
            # Match punctuation
            if {[string first $ch "{}()\[\],;."] != -1} {
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
                if {[regexp -start $i -indices {"[^"]*"} $text matchIdx]} {
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

    # Parse a token stream into an AST
    proc parse {tokens} {
        set ast [dict create]
        set len [llength $tokens]
        set i 0
        
        while {$i < $len} {
            set token [lindex $tokens $i]
            
            # Look for Module Definition: ModuleName DEFINITIONS ::= BEGIN
            if {$i + 3 < $len && [lindex $tokens [expr {$i+1}]] eq "DEFINITIONS" && [lindex $tokens [expr {$i+2}]] eq "::=" && [lindex $tokens [expr {$i+3}]] eq "BEGIN"} {
                set moduleName $token
                set moduleAst [dict create types [dict create] values [dict create]]
                set i [expr {$i + 4}]
                
                # Parse body of module
                while {$i < $len && [lindex $tokens $i] ne "END"} {
                    set ident [lindex $tokens $i]
                    
                    if {[lindex $tokens [expr {$i+1}]] eq "::="} {
                        set rhsIdx [expr {$i + 2}]
                        set rhsToken [lindex $tokens $rhsIdx]
                        
                        if {$rhsToken eq "SEQUENCE" && [lindex $tokens [expr {$rhsIdx+1}]] eq "\{"} {
                            # Parse SEQUENCE
                            set i [expr {$rhsIdx + 2}]
                            set fields [dict create]
                            while {$i < $len && [lindex $tokens $i] ne "\}"} {
                                set fieldName [lindex $tokens $i]
                                incr i
                                set fieldType [lindex $tokens $i]
                                
                                # Handle OCTET STRING, BIT STRING
                                if {$fieldType in {"OCTET" "BIT"} && [lindex $tokens [expr {$i+1}]] eq "STRING"} {
                                    set fieldType "$fieldType STRING"
                                    incr i
                                }
                                
                                dict set fields $fieldName type $fieldType
                                incr i
                                if {[lindex $tokens $i] eq ","} {
                                    incr i
                                }
                            }
                            dict set moduleAst types $ident type "SEQUENCE"
                            dict set moduleAst types $ident components $fields
                            incr i ;# skip closing brace
                        } elseif {$rhsToken eq "CHOICE" && [lindex $tokens [expr {$rhsIdx+1}]] eq "\{"} {
                            # Parse CHOICE
                            set i [expr {$rhsIdx + 2}]
                            set fields [dict create]
                            while {$i < $len && [lindex $tokens $i] ne "\}"} {
                                set fieldName [lindex $tokens $i]
                                incr i
                                set fieldType [lindex $tokens $i]
                                
                                if {$fieldType in {"OCTET" "BIT"} && [lindex $tokens [expr {$i+1}]] eq "STRING"} {
                                    set fieldType "$fieldType STRING"
                                    incr i
                                }
                                
                                dict set fields $fieldName type $fieldType
                                incr i
                                if {[lindex $tokens $i] eq ","} {
                                    incr i
                                }
                            }
                            dict set moduleAst types $ident type "CHOICE"
                            dict set moduleAst types $ident components $fields
                            incr i ;# skip closing brace
                        } else {
                            # Simple type assignment
                            set fieldType $rhsToken
                            if {$fieldType in {"OCTET" "BIT"} && [lindex $tokens [expr {$rhsIdx+1}]] eq "STRING"} {
                                set fieldType "$fieldType STRING"
                                set i [expr {$rhsIdx + 2}]
                            } else {
                                set i [expr {$rhsIdx + 1}]
                            }
                            dict set moduleAst types $ident type $fieldType
                        }
                    } else {
                        incr i
                    }
                }
                
                dict set ast $moduleName $moduleAst
                if {$i < $len && [lindex $tokens $i] eq "END"} {
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
