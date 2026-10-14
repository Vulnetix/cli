// Base64 blobs that start with eyJ but are not three JSON segments.
const state = "eyJwYWdlIjoxLCJzaXplIjoyMH0";
const cursor = "eyJwYWdlIjoxLCJzaXplIjoyMH0.eyJub3RqdXN0YmFzZTY0.not-valid-base64-json!!x";
const garbage = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIi.@@sample:[A-Za-z0-9]{20}@@";
