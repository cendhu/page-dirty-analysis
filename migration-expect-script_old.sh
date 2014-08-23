#!/usr/bin/expect
set timeout 600
set src [lindex $argv 0]
set dest [lindex $argv 1]
set tport [lindex $argv 2]
set mport [lindex $argv 3]
set rate [lindex $argv 4]

spawn telnet $src $tport

expect "(qemu)"
send "migrate_set_speed $rate\r"
expect "(qemu)"
send "migrate tcp:$dest:$mport\r"
expect "(qemu)"
send "info migrate\r"
expect "(qemu)"
