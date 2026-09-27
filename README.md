# doh-research

Research and implementation of raw DNS (RFC 1035) query crafting and DNS-over-HTTPS (DoH, RFC 8484) wire-format packet communication in Python.

## Overview

- **RFC 1035 Wire Format**: Low-level DNS packet crafting using Python `struct` and Big-Endian packing.
- **DoH Transport (RFC 8484)**: Direct HTTP POST transport using `application/dns-message` against endpoints like Cloudflare (`1.1.1.1`).
- **Response Parsing**: Unpacking DNS headers, parsing status flags (`RCODE`), handling compression pointers (`0xC0`), and extracting resource record data (`RDATA`).

## Structure

- `DNS_Research.py`: Core client implementation containing query builder, UDP/DoH transport, and RFC 1035 response parser.
