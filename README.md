# roxy

Roxy is a caching proxy written in rust. The purpose of roxy is to provide a lightweight, and performant proxy that forwards requests to other upstreams (either proxies or direct) while allowing for content-addressible caching to occur.

# Features
- Configurable caching based on heuristics + configs to compute the cache key (based on request)
- Caching occurs at the content level, thus connection MITM is required
- Configurable upstream proxy support
- HTTP proxy interface
- Allow for emulation of JA3, JA4, and Akamai HTTP/2 fingerprint
- Support HTTP2 and HTTP1 protocols
