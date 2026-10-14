import { verify } from "../auth";

const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtYmlsbGluZyIsInJvbGUiOiJzZXJ2aWNlIiwiaWF0IjoxNzYwMDAwMDAwfQ.@@sample:[A-Za-z0-9_\-]{43}@@";

it("rejects a token signed with another key", () => {
  expect(() => verify(token)).toThrow();
});
