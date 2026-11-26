# Benchmarks

What Resguardo costs: how fast it scans, and how much latency it adds to a request. Measured with [`tools/bench`](../tools/bench/src/main.rs) against the mock provider on the same machine, so the network adds nothing and the numbers are Resguardo's own ([ADR 0016](adr/0016-measuring-accuracy-and-latency.md)).

```console
$ cargo run --release -p resguardo-bench
```

## Machine

A standard GitHub Actions runner (`ubuntu-latest`), measured by the manual [`lab` workflow](../.github/workflows/lab.yml) on 2026-11-26: Linux 7.0 on Azure, x86_64, 4 vCPUs of an AMD EPYC 9V74, 15 GiB of memory, release build. A runner is a shared virtual machine, so take the numbers as an order of magnitude. The workflow prints the machine next to the results every time it runs; run the benchmark on your own hardware before relying on them.

## Scanning

Spanish support text with a DNI, an email address and a Base64 fragment every 250 bytes: ordinary text with frequent findings.

| Text | Per scan | Throughput |
| --- | --- | --- |
| 1 KB | 58 µs | 17.4 MB/s |
| 16 KB | 896 µs | 18.3 MB/s |
| 256 KB | 14.9 ms | 17.5 MB/s |

Scanning is linear in the size of the text. A typical chat request of a few kilobytes costs well under a millisecond. It runs on Tokio's blocking pool, so a large request does not slow down the others.

## Latency added end to end

400 sequential requests after 20 warm-up ones. "Added" is the difference with the same request sent straight to the mock. The decision entry of every request is signed and, with `fsync` on (the default), flushed to disk before the request leaves.

| Path | p50 | p95 | p99 | Added p50 | Added p99 |
| --- | --- | --- | --- | --- | --- |
| Direct to the mock | 72 µs | 89 µs | 101 µs | — | — |
| Through Resguardo, `fsync` on | 591 µs | 779 µs | 4.1 ms | 519 µs | 4.0 ms |
| Through Resguardo, `fsync` off | 324 µs | 358 µs | 381 µs | 252 µs | 280 µs |
| Through Resguardo, redacting a DNI, `fsync` on | 606 µs | 731 µs | 4.1 ms | 534 µs | 4.0 ms |

## What the numbers say

- **Resguardo adds about half a millisecond at p50, with the receipt flushed to disk.** Without `fsync`, about a quarter of a millisecond: authentication, strict parsing, scanning, policy, signing the receipt and the extra hop.
- **The p99 with `fsync` is about 4 ms, and that is the disk:** now and then a flush takes longer. Without `fsync` the p99 stays under 0.3 ms. One `fsync` per request is the price of "the receipt is on disk before anything leaves"; the outcome entry does not wait for its own `fsync` (ADR 0015).
- **The disk matters more than Resguardo.** On a 2017 laptop whose `fsync` takes about 10 ms, the same run added about 10 ms per request. Measure on the disk you will use.
- **Redaction costs nothing visible** next to the disk.
- Against a real provider, which answers in hundreds of milliseconds or seconds, the added latency is a small fraction.

## Limits

Sequential requests on one machine: this measures cost per request, not throughput under concurrency. With `fsync` on, concurrent requests queue on the log, so throughput is bounded by the disk's flush rate. Group commit is listed in `LATER.md`.
