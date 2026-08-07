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
| list products | `queryTeaProducts` | 200 | yes | 31.22 ms | pass |
| list product releases (full page) | `queryTeaProductReleases` | 200 | yes | 84.77 ms | pass |
| list component releases (full page, descending) | `queryTeaComponentReleases` | 200 | yes | 72.06 ms | pass |
| read one product | `getTeaProductByUuid` | 200 | yes | 32.78 ms | pass |
| read one product release | `getTeaProductReleaseByUuid` | 200 | yes | 29.79 ms | pass |
| releases of one product | `getReleasesByProductId` | 200 | yes | 42.75 ms | pass |
| component release with latest collection | `getComponentReleaseById` | 200 | yes | 33.23 ms | pass |
| latest collection | `getLatestCollection` | 200 | yes | 49.01 ms | pass |
| resolve a TEI | `discoveryByTei` | 200 | yes | 27.22 ms | pass |
| artifact metadata | `getLatestArtifact` | 200 | yes | 32.22 ms | pass |


[Back to the summary](../)
