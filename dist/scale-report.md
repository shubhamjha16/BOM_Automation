# Scale measurement

Budget: **30s** wall clock and **1024 MB** peak for a 50,000-component SBOM.

## The largest single document

- 50,000 components, 21.1 MB of JSON
- **3.86s** wall clock (3.56s CPU), 0.077 ms per component
- **208.5 MB** peak RSS
- 50,000 entities scored, nothing dropped, score 56.1
- within budget: **True**

## Concurrent five-lane assessments

20 assessments × 5 lanes, 2,000 components in the SBOM lane plus real documents in the other four, in **4.36s** (0.22s each, amortised — per-assessment latency is the p95 column, not this).

Throughput across the run was 11,462 components per second — within noise of the single-document rate above. **Concurrency shares the throughput rather than adding to it**, which is the expected consequence of scoring being pure Python: twenty assessments at once finish in about the time twenty assessments in series would take. What concurrency buys is that no client waits behind another client's whole queue, not that the machine does more work.

| Lane | n | p50 ms | p95 ms | max ms |
| --- | ---: | ---: | ---: | ---: |
| aibom | 20 | 698.47 | 2338.67 | 2338.9 |
| cbom | 20 | 775.43 | 2339.41 | 2367.38 |
| hbom | 20 | 879.39 | 2339.05 | 2339.26 |
| qbom | 20 | 879.02 | 2338.81 | 2338.96 |
| sbom | 20 | 2339.55 | 2374.43 | 2440.2 |

- lane intervals overlap: **True**
- every submission reconstructs all five lifecycles from logs: **True**
- peak RSS across the run: **208.5 MB**

## What the overlap does and does not mean

The lane intervals overlap, and that is what the isolation properties rest on: a lane that times out or raises does not stop the other four. It is not a speedup. Scoring is pure Python and holds the GIL, so five lanes over one document cost about what five lanes in series cost, plus scheduling. The measurement behind that statement is recorded in `services/graph/laneRunner.py`. Reporting the overlap as a performance win would be the kind of unfounded figure §11 exists to prevent.

## Cost

Reported as CPU-seconds and peak memory, not as currency. The currency figure depends on an instance price and a utilisation assumption, and a number this repository invented would be quoted back at it.
