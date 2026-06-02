#!/usr/bin/env tclsh

package require tcltest

set testdir [file dirname [file normalize [info script]]]
set root [file dirname $testdir]

lappend auto_path $root
set muttclLib [file join $root deps muttcl lib]
if {[file isdirectory $muttclLib]} {
    lappend auto_path $muttclLib
}
package require asn1

tcltest::configure -testdir $testdir
tcltest::configure -verbose {p s}

tcltest::runAllTests
tcltest::cleanupTests
