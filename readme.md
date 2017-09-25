# pcap_test

Reads packet and displays it.

## Install

```
sudo apt install libpcap*
git clone https://github.com/0xrgb/pcap_test.git
cd pcap_test
make
```

## Run

```
sudo ./pcap_test eth0
```

## TODO

+ Refactor codes to enhance readability

## Issues

+ Undefined reference to `pcap_open_live`
	+ [Order of library is important](https://stackoverflow.com/questions/45135/why-does-the-order-in-which-libraries-are-linked-sometimes-cause-errors-in-gcc)
	+ Should use `gcc <source> -lpcap`, not `gcc -lpcap <source>`
+ `eth0: socket: Invalid argument`
	+ [It is a problem of WSL](https://github.com/Microsoft/BashOnWindows/issues/69#issuecomment-208574945)
	+ Should use real linux (or VM)
