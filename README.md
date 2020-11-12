# Monitarp
### a Network Device Detection Tool using the Address Resolution Protocol



## How to use?
Place the files inside the same directory.
run `sudo python3 monitarp.py` to use the program with default options.



## Optional Flags:
* `-s/--stealth` does not send ARP requests when set
* `-o/--output` outputs gathered data to given filename. requires a `string`.
* `-L/--log` writes log information to filename. requires a `string`.
* `-r/--range` sets the IP range, for example 192.168.0.0/24. requires a `string`.
* `-i/--interface` changes the network interface which is used to send and receive packets. requires a `string`.
* `-d/--delay` changes the delay between the ARP requests . requires a `float`.
* `-m/--mac` changes the MAC address which is used as source in the ARP requests. requires a `string`.
* `-l/--limit` limits the gathered data when set, resulting in more accurate results
* `-v/--verbose` outputs more data to the screen
* `-R/--repeat` does not repeat the scanning of the IP range when done
* `-t/--timout` removes device from the screen when the timout exceeds and when `--log` is set it marks the device as `OFFLINE`. requires a `int`.
* `-b/--blur` blurs data when using the GUI. requires a `string`.
* `--nogui` does not display any information on the screen
