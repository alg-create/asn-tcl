#!/usr/bin/env tclsh

set test_dir [file dirname [info script]]
cd $test_dir
set test_files [glob -nocomplain *_test.tcl]

set total 0
set passed 0
set failed 0

puts "========================================"
puts "  ASN.1 Parser Test Harness "
puts "========================================"

foreach test_file $test_files {
    set filename [file tail $test_file]
    puts "Running: $filename"
    
    # Run the test file in a new tclsh process
    if {[catch {exec tclsh $test_file} result]} {
        puts "\[FAIL\] $filename"
        puts "Output:\n$result"
        incr failed
    } else {
        puts "\[PASS\] $filename"
        # Uncomment the next line if you want to see test output on success
        # puts "$result"
        incr passed
    }
    incr total
    puts "----------------------------------------"
}

puts "Summary: $total tests run, $passed passed, $failed failed."
if {$failed > 0} {
    exit 1
} else {
    exit 0
}
