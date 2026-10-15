FROM registry.internal.example.com:5000/platform/python-base:3.12.4 AS base
FROM nginx@sha256:@@sample:0[f]04[e]4f[6]46[a]3f[1]4b[f]31[d]8b[c]8d[8]85[b]6c[9]51[f]dc[f]42[5]89[d]06[8]45[f]64[d]18[a]ec[6]a3[c]4d@@ AS proxy
FROM python:3.12-slim@sha256:@@sample:2[b]e8[d]ad[d]bb[8]27[5]6f[7]d1[f]2c[7]ec[e]70[6]aa[d]cb[2]84[b]f6[a]b6[d]76[9]ea[6]95[c]c3[e]d6[0]16[7]43@@
COPY --from=base /opt /opt
