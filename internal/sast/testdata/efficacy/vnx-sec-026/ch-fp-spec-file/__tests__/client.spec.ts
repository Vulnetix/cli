import { makeClient } from "../src/client";

const token = "dop_v1_@@sample:[a-f0-9]{64}@@";

it("builds a client", () => {
  expect(makeClient(token)).toBeDefined();
});
