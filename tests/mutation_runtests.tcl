#!/usr/bin/env tclsh

set testdir [file dirname [file normalize [info script]]]
set root [file dirname $testdir]

lappend auto_path $root
set muttclLib [file join $root deps muttcl lib]
if {[file isdirectory $muttclLib]} {
    lappend auto_path $muttclLib
}

package require tcltest
package require asn1

set ::mutationTestFailed 0

rename ::tcltest::cleanupTests ::tcltest::cleanupTestsOriginal
proc ::tcltest::cleanupTests {} {
    if {$::tcltest::numTests(Failed) > 0} {
        set ::mutationTestFailed 1
    }
    uplevel 1 ::tcltest::cleanupTestsOriginal
}

if {[llength $argv] == 0} {
    set testFiles [lsort [glob -nocomplain [file join $testdir *.test]]]
} else {
    set testFiles {}
    foreach testFile $argv {
        lappend testFiles [file normalize $testFile]
    }
}

foreach testFile $testFiles {
    puts "==> [file tail $testFile]"
    set ::argv {}
    if {[catch {uplevel #0 [list source $testFile]} message options]} {
        puts stderr $message
        puts stderr [dict get $options -errorinfo]
        set ::mutationTestFailed 1
    }
    if {$::mutationTestFailed} {
        exit 1
    }
}

exit $::mutationTestFailed
