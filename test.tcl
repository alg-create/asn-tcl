set root [pwd]
lappend auto_path $root
package require asn1

foreach f {01-simple.asn 02-tagging.asn 03-imports.asn 04-constraints.asn} {
    set path [file join $root tests modules $f]
    puts "--- $f ---"
    set parsed [asn1::parse_file $path]
    puts $parsed
}
