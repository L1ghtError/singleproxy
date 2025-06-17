## DNS Proxy
### How to build
```bash
$ git clone --recursive https://github.com/L1ghtError/singleproxy.git
$ cd singleproxy
$ mkdir build
$ cd build
$ cmake ..
$ cmake --build .
$ sudo ./dns_proxy
```
To start using this proxy specify `nameserver` in `/etc/resonv.conf`
> **Thid party libs:**
> - [cJSON](https://github.com/DaveGamble/cJSON) for parsing json config file
