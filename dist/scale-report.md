# Scale measurement

Budget: **30s** wall clock and **1024 MB** peak for a 50,000-component SBOM.

## The largest single document

- 50,000 components, 21.1 MB of JSON
- **5.05s** wall clock (4.27s CPU), 0.101 ms per component
- **208.7 MB** peak RSS
- 50,000 entities scored, nothing dropped, score 56.1
- within budget: **True**

## Concurrent five-lane assessments

20 assessments × 5 lanes, 2,000 components in the SBOM lane plus real documents in the other four, in **8.48s** (0.42s each, amortised — per-assessment latency is the p95 column, not this).

Throughput across the run was 5,896 components per second — within noise of the single-document rate above. **Concurrency shares the throughput rather than adding to it**, which is the expected consequence of scoring being pure Python: twenty assessments at once finish in about the time twenty assessments in series would take. What concurrency buys is that no client waits behind another client's whole queue, not that the machine does more work.

| Lane | n | p50 ms | p95 ms | max ms |
| --- | ---: | ---: | ---: | ---: |
| aibom | 20 | 1326.2 | 2760.29 | 3056.77 |
| cbom | 20 | 1364.02 | 2889.65 | 3105.57 |
| hbom | 20 | 1352.77 | 2760.51 | 3159.54 |
| qbom | 20 | 1325.69 | 2760.23 | 2760.41 |
| sbom | 20 | 3390.34 | 3600.04 | 3601.19 |

- lane intervals overlap: **True**
- every submission reconstructs all five lifecycles from logs: **True**
- peak RSS across the run: **208.7 MB**

## What the overlap does and does not mean

The lane intervals overlap, and that is what the isolation properties rest on: a lane that times out or raises does not stop the other four. It is not a speedup. Scoring is pure Python and holds the GIL, so five lanes over one document cost about what five lanes in series cost, plus scheduling. The measurement behind that statement is recorded in `services/graph/laneRunner.py`. Reporting the overlap as a performance win would be the kind of unfounded figure §11 exists to prevent.

## Cost

Reported as CPU-seconds and peak memory, not as currency. The currency figure depends on an instance price and a utilisation assumption, and a number this repository invented would be quoted back at it.
