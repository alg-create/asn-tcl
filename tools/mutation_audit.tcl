#!/usr/bin/env tclsh

proc usage {} {
    puts stderr "usage: tclsh tools/mutation_audit.tcl ?options?"
    puts stderr "options:"
    puts stderr "  -target FILE             target to mutate (default: asn1_parser.tcl)"
    puts stderr "  -mutators LIST           mutator categories, for example {arithmetic logical}"
    puts stderr "  -limit N                 run at most N mutants after filtering"
    puts stderr "  -start N                 1-based filtered mutant index to start at"
    puts stderr "  -timeout-ms N            per-mutant timeout (default: 30000)"
    puts stderr "  -baseline-timeout-ms N   baseline timeout (default: 120000)"
    puts stderr "  -progress-file FILE      progress log (default: .tmp/mutation_audit_progress.log)"
    puts stderr "  -keep-scratch BOOL       keep disposable audit copy (default: 0)"
    exit 2
}

proc optionValue {options key} {
    return [dict get $options $key]
}

proc parseOptions {argv} {
    set options [dict create \
        -target asn1_parser.tcl \
        -mutators {} \
        -limit 0 \
        -start 1 \
        -timeout-ms 30000 \
        -baseline-timeout-ms 120000 \
        -progress-file [file join .tmp mutation_audit_progress.log] \
        -keep-scratch 0]

    set i 0
    while {$i < [llength $argv]} {
        set key [lindex $argv $i]
        if {![dict exists $options $key]} {
            usage
        }
        incr i
        if {$i >= [llength $argv]} {
            usage
        }
        dict set options $key [lindex $argv $i]
        incr i
    }

    foreach key {-limit -start -timeout-ms -baseline-timeout-ms} {
        set value [dict get $options $key]
        if {![string is integer -strict $value] || $value < 0} {
            error "$key must be a non-negative integer"
        }
    }
    if {[dict get $options -start] < 1} {
        error "-start must be at least 1"
    }

    return $options
}

proc appendLog {path message} {
    file mkdir [file dirname $path]
    set out [open $path a]
    puts $out $message
    close $out
    puts $message
    flush stdout
}

proc copyFile {source dest} {
    file mkdir [file dirname $dest]
    file copy -force $source $dest
}

proc copyTree {source dest} {
    file mkdir $dest
    foreach entry [glob -nocomplain -directory $source *] {
        set target [file join $dest [file tail $entry]]
        if {[file isdirectory $entry]} {
            copyTree $entry $target
        } else {
            copyFile $entry $target
        }
    }
}

proc defaultTestFiles {root} {
    set result {}
    foreach testFile [lsort [glob -nocomplain [file join $root tests *.test]]] {
        if {[file tail $testFile] eq "muttcl_integration.test"} {
            continue
        }
        lappend result [file join tests [file tail $testFile]]
    }
    return $result
}

proc makeScratchProject {root target testFiles} {
    set handle [file tempfile scratch]
    close $handle
    file delete $scratch
    file mkdir $scratch

    copyFile [file join $root $target] [file join $scratch $target]
    copyFile [file join $root pkgIndex.tcl] [file join $scratch pkgIndex.tcl]
    copyFile [file join $root tests mutation_runtests.tcl] [file join $scratch tests mutation_runtests.tcl]

    foreach testFile $testFiles {
        copyFile [file join $root $testFile] [file join $scratch $testFile]
    }

    if {[file isdirectory [file join $root tests modules]]} {
        copyTree [file join $root tests modules] [file join $scratch tests modules]
    }

    return [file normalize $scratch]
}

proc readFile {path} {
    set in [open $path r]
    set data [read $in]
    close $in
    return $data
}

proc writeFile {path data} {
    set out [open $path w]
    puts -nonewline $out $data
    close $out
}

proc mutationLabel {mutation} {
    set replacement [dict get $mutation replacement]
    if {$replacement eq ""} {
        set replacement "<empty>"
    }
    return [format "%s line=%d col=%d %s -> %s" \
        [dict get $mutation id] \
        [dict get $mutation line] \
        [dict get $mutation column] \
        [dict get $mutation original] \
        $replacement]
}

set root [file normalize [file join [file dirname [info script]] ..]]
cd $root

set options [parseOptions $argv]
set progressFile [file normalize [optionValue $options -progress-file]]
file mkdir [file dirname $progressFile]
set out [open $progressFile w]
puts $out "mutation audit started [clock format [clock seconds] -format {%Y-%m-%d %H:%M:%S}]"
close $out

lappend auto_path $root
lappend auto_path [file join $root deps muttcl lib]
package require asn1
package require tclmut 0.1

set target [optionValue $options -target]
set testFiles [defaultTestFiles $root]
set scratch [makeScratchProject $root $target $testFiles]
set targetPath [file join $scratch $target]
set originalSource [readFile $targetPath]
set summary [dict create killed 0 survived 0 invalid 0 timeout 0 total 0]

appendLog $progressFile "target=$target"
appendLog $progressFile "scratch=$scratch"
appendLog $progressFile "tests=[join $testFiles { }]"

try {
    set testCommand [list [info nameofexecutable] tests/mutation_runtests.tcl {*}$testFiles]

    appendLog $progressFile "baseline START"
    set baseline [::tclmut::runner::runProcessWithTimeout \
        $testCommand \
        [optionValue $options -baseline-timeout-ms] \
        $scratch]
    appendLog $progressFile "baseline DONE status=[dict get $baseline status] elapsed=[dict get $baseline elapsed]"
    if {[dict get $baseline status] ne "passed"} {
        appendLog $progressFile [dict get $baseline output]
        exit 1
    }

    set tree [::tclmut::parser::parseScript $originalSource -file $target]
    set mutations [::tclmut::mutations::generate \
        $originalSource \
        -file $target \
        -tree $tree \
        -mutators [optionValue $options -mutators]]

    set start [optionValue $options -start]
    set limit [optionValue $options -limit]
    set selected {}
    set index 0
    foreach mutation $mutations {
        incr index
        if {$index < $start} {
            continue
        }
        if {$limit > 0 && [llength $selected] >= $limit} {
            break
        }
        lappend selected [list $index $mutation]
    }

    dict set summary total [llength $selected]
    appendLog $progressFile "mutants total=[llength $mutations] selected=[llength $selected] start=$start limit=$limit mutators=[optionValue $options -mutators]"

    set selectedIndex 0
    foreach item $selected {
        incr selectedIndex
        lassign $item originalIndex mutation
        set label [mutationLabel $mutation]
        appendLog $progressFile [format "mutant START %d/%d originalIndex=%d %s" \
            $selectedIndex [llength $selected] $originalIndex $label]

        set mutantSource [::tclmut::mutations::apply $originalSource $mutation]
        writeFile $targetPath $mutantSource
        set result [::tclmut::runner::runProcessWithTimeout \
            $testCommand \
            [optionValue $options -timeout-ms] \
            $scratch]
        writeFile $targetPath $originalSource

        set classification [::tclmut::runner::classifyProcessStatus [dict get $result status]]
        dict incr summary $classification
        appendLog $progressFile [format "mutant DONE %d/%d originalIndex=%d class=%s elapsed=%d %s" \
            $selectedIndex \
            [llength $selected] \
            $originalIndex \
            $classification \
            [dict get $result elapsed] \
            $label]
        if {$classification ne "killed"} {
            appendLog $progressFile "mutant OUTPUT $label"
            appendLog $progressFile [string trim [dict get $result output]]
        }
    }

    appendLog $progressFile "summary $summary"
} finally {
    catch {writeFile $targetPath $originalSource}
    if {![optionValue $options -keep-scratch]} {
        catch {file delete -force $scratch}
    } else {
        appendLog $progressFile "scratch kept at $scratch"
    }
}
