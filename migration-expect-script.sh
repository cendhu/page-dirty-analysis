#!/usr/bin/expect
set timeout 600
set addr [lindex $argv 0]
set size [lindex $argv 1]
set fname [lindex $argv 2]
set hcpu [lindex $argv 3]
set index [lindex $argv 4]
set src [lindex $argv 5]
set tport [lindex $argv 6]

spawn telnet $src $tport

expect "(qemu)"
send "memsave $addr $size $fname\r"
expect "(qemu)"
