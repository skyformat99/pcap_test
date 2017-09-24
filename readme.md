# pcap_test

Reads packet and displays it.

## TODO

+ ipv4
+ tcp

## Issues

+ Undefined reference to `pcap_open_live`
	+ [Order of library is important](https://stackoverflow.com/questions/45135/why-does-the-order-in-which-libraries-are-linked-sometimes-cause-errors-in-gcc).
	+ Should use `gcc <source> -lpcap`, not `gcc -lpcap <source>`.
+ `eth0: scoket: Invalid argument`
	+ [It is a problem of WSL](https://github.com/Microsoft/BashOnWindows/issues/69#issuecomment-208574945).
	+ Should use real linux (or VM).
