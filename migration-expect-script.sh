#!/usr/bin/expect
set timeout 600
set addr [lindex $argv 0]
set size [lindex $argv 1]
set src [lindex $argv 2]
set tport [lindex $argv 3]

spawn telnet $src $tport
set c 0
while {1} {
  set filename "\"/tmp/file"
  append filename $c
  append filename ".dump\""
  expect "(qemu)"
  send "pmemsave $addr $size $filename\r"
  sleep 2
  incr c 2
}
