#!/usr/bin/expect
set timeout 600
set addr [lindex $argv 0]
set size [lindex $argv 1]
set fname [lindex $argv 3]
#set hcpu [lindex $argv 3]
#set index [lindex $argv 4]
set src [lindex $argv 2]
set tport [lindex $argv 4]

spawn telnet $src $tport
while {1} {
  expect "(qemu)"
  send "pmemsave $addr $size $fname\r"
  sleep 2
}
