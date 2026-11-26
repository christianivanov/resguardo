# Benchmarks

What Resguardo costs: how fast it scans, and how much latency it adds to a request. Measured with [`tools/bench`](../tools/bench/src/main.rs) against the mock provider on the same machine, so the network adds nothing and the numbers are Resguardo's own ([ADR 0016](adr/0016-measuring-accuracy-and-latency.md)).

```console
$ cargo run --release -p resguardo-bench
```

## Machine

A 2017 MacBook Pro: macOS, x86_64, 4 logical CPUs, APFS on the internal SSD, release build. A current Linux server is several times faster, and its `fsync` is usually far cheaper. Run the benchmark on your own hardware before relying on these numbers.

## Scanning

Spanish support text with a DNI, an email address and a Base64 fragment every 250 bytes: ordinary text with frequent findings.

| Text | Per scan | Throughput |
| --- | --- | --- |
| 1 KB | 253 µs | 4.0 MB/s |
| 16 KB | 4.2 ms | 3.9 MB/s |
| 256 KB | 57.2 ms | 4.6 MB/s |

Scanning is linear in the size of the text. A typical chat request of a few kilobytes costs about a millisecond. It runs on Tokio's blocking pool, so a large request does not slow down the others.

## Latency added end to end

400 sequential requests after 20 warm-up ones. "Added" is the difference with the same request sent straight to the mock. The decision entry of every request is signed and, with `fsync` on (the default), flushed to disk before the request leaves.

| Path | p50 | p95 | p99 | Added p50 | Added p99 |
| --- | --- | --- | --- | --- | --- |
| Direct to the mock | 193 µs | 339 µs | 1.5 ms | — | — |
| Through Resguardo, `fsync` on | 10.9 ms | 14.4 ms | 20.6 ms | 10.7 ms | 19.1 ms |
| Through Resguardo, `fsync` off | 669 µs | 1.7 ms | 3.2 ms | 475 µs | 1.7 ms |
| Through Resguardo, redacting a DNI, `fsync` on | 10.7 ms | 13.3 ms | 16.0 ms | 10.5 ms | 14.4 ms |

## What the numbers say

- **Without `fsync`, Resguardo adds about half a millisecond.** That covers authentication, strict parsing, scanning, policy, signing the receipt and the extra hop.
- **With `fsync`, the disk dominates.** This laptop takes about 10 ms per `fsync`; on a server SSD it is usually around a millisecond. One `fsync` per request is the price of "the receipt is on disk before anything leaves". The outcome entry does not wait for its own `fsync` (ADR 0015).
- **Redaction costs nothing visible** next to the network and the disk.
- Against a real provider, which answers in hundreds of milliseconds or seconds, the added latency is a small fraction.

## Limits

Sequential requests on one machine: this measures cost per request, not throughput under concurrency. With `fsync` on, concurrent requests queue on the log, so throughput is bounded by the disk's flush rate. Group commit is listed in `LATER.md`.
