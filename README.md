# simplesocks
A basic SOCKSv5 proxy written in Go.

TODO: add blacklisting based on site, time, and client.

# Simple Browse Control SOCKS proxy
Reference RFC: https://tools.ietf.org/html/rfc1928

# Testing from command line
```bash
curl -v -x socks5h://localhost:3128 https://google.com
```
