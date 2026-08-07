---
title: Performance
weight: 9
description: "cold and cached latency, reported separately"
---


cold and cached latency, reported separately

| Cases | Passed | Failed | Advisory |
|---:|---:|---:|---:|
| 10 | 10 | 0 | 0 |

## Performance

Not measured: this run replayed a recorded directory, so no timings were taken; the figures in that run's report.json are the measured ones.

### performance cases

| Case | Operation | Status | Schema | Latency | Verdict |
|---|---|---:|---|---:|---|
| list products | `queryTeaProducts` | 200 | yes | 23.78 ms | pass |
| list product releases (full page) | `queryTeaProductReleases` | 200 | yes | 47.16 ms | pass |
| list component releases (full page, descending) | `queryTeaComponentReleases` | 200 | yes | 71.28 ms | pass |
| read one product | `getTeaProductByUuid` | 200 | yes | 21.70 ms | pass |
| read one product release | `getTeaProductReleaseByUuid` | 200 | yes | 41.77 ms | pass |
| releases of one product | `getReleasesByProductId` | 200 | yes | 27.87 ms | pass |
| component release with latest collection | `getComponentReleaseById` | 200 | yes | 49.11 ms | pass |
| latest collection | `getLatestCollection` | 200 | yes | 26.33 ms | pass |
| resolve a TEI | `discoveryByTei` | 200 | yes | 24.97 ms | pass |
| artifact metadata | `getLatestArtifact` | 200 | yes | 29.75 ms | pass |


[Back to the summary](../)
