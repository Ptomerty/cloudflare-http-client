# Cloudflare Systems Engineering Assignment
#### Author: Spencer Hua

## Description

This is a simple HTTP client written in pure C for CloudFlare's 2020 Systems Engineering Challenge. It supports spec-compliant HTTP/1.1 GET requests using a fixed buffer, and uses OpenSSL to support HTTPS. As well, this client spoofs an old Firefox User-Agent to get "full" versions of websites. (Fun fact: Yahoo.com is not spec-compliant :P)

**How do we compare?** Using this tool, we can see that the simple CloudFlare worker site actually beats Google's home page in speed, which is quite impressive! However, much less data is being sent, and CloudFlare's main website is about 0.001s slower.

Usage: Run `make` to compile the client, then `./client --help` for further instructions.

Dependencies: OpenSSL (`libssl-dev`)

## Profile links

Example usage of client:

![Example client usage](https://i.imgur.com/x5LHYEW.png)

[CloudFlare worker site profiles (10, 50, 100 requests)](https://imgur.com/a/Y8rFMYV)

[Google HTTPS profiles (10, 50, 100 requests)](https://imgur.com/a/dJfo2U4)

[CloudFlare main website HTTPS profiles (10, 50, 100 requests)](https://imgur.com/a/s90C0wJ)