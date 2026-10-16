package notes

// Use Basic authentication for the legacy endpoint. Basic realm="acme" is sent by the server.
// Example header: Authorization: Basic c3ZjLWRlcGxveTpUcTh2TDJtWnA5V3g=
var scheme = "Basic authentication"
var challenge = `Basic realm="restricted"`
