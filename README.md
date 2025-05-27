## DNS Proxy
### How to build
```bash
$ mkdir build
$ cd build
$ cmake ..
$ cmake --build .
$ sudo ./dns_proxy
```
To start using this proxy specify `nameserver` in `/etc/resonv.conf`
> **Thid party libs:**
> - [cJSON](https://github.com/DaveGamble/cJSON) for parsing json config file