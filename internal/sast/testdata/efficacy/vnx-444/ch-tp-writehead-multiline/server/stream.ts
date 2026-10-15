import { ServerResponse } from "http";

export function stream(res: ServerResponse, size: number) {
  res.writeHead(200, {
~>    "transfer-encoding": "chunked",
    "content-length": String(size),
  });
}
