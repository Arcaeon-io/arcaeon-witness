# Load test: writes per pin under 100 concurrent pinners

`node tools/loadtest.js [--pinners 100] [--pins 3] [--shadow] [--delay-ms 4] [--json]` runs the real `api/pin.js` against the test suite's fake of the GitHub contents API, with a small random delay on every store call so concurrent requests interleave. Each pinner has its own key and namespace and pins one after another, rows growing. Nothing reaches a network. The numbers say what the write path does under contention, not how fast GitHub is.

## Results, Sat 2026-10-31, on `main`

| run | accepted | writes per pin (public + private) | lost CAS races | pending leaves kept | p50 / p95 |
|---|---|---|---|---|---|
| 100 pinners x 3, shadow off | 300 of 300 | 2 + 1 = 3 | 0 | (off) | 44 / 54 ms |
| 100 pinners x 3, shadow on | 300 of 300 | 2 + 1.107 = 3.107 | 842 | 32 of 300 (268 dropped) | 140 / 171 ms |
| 10 pinners x 3, shadow on | 30 of 30 | 2 + 1.7 = 3.7 | 41 | 21 of 30 (9 dropped) | 33 / 45 ms |
| 100 pinners x 3, shadow on, no delay | 300 of 300 | 2 + 1.047 = 3.047 | 865 | 14 of 300 (286 dropped) | 107 / 114 ms |

What it shows:

- **Every pin lands, and the public record costs exactly 2 writes a pin** (the numbered record and latest.json), at any concurrency. The meter adds 1 private write a pin, each key on its own file, so it never contends here.
- **The shadow batch run does not hold up under concurrency.** Every accepted pin adds its leaf to one shared pending document by compare and swap, with 3 tries. At 100 concurrent pinners about 9 in 10 leaves are dropped after losing every try; even at 10, about 3 in 10. The pin is not affected (`recordAcceptedSafe` logs the miss and the reconciler is built to catch it), but a batch root over such a run covers few of its pins. This is the measured case for moving the pending state off the contents API (pull request 3, `WITNESS_USAGE_STORE=postgres`), and for a design that does not funnel every pin through one document: more tries with backoff, or one leaf file per pin gathered by the sealer.
- Lost races cost extra private write attempts (`private` above 1), not extra landed writes.

These are runs of this code against a fake with tiny delays; real GitHub latency and its own rate limits would make the contention worse, not better.
