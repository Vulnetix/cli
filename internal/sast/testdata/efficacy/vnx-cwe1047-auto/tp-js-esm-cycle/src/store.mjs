import { log } from "./logger.mjs";

const entries = [];

export default {
  push(entry) {
    entries.push(entry);
  },
  reset() {
    entries.length = 0;
    log('store reset');
  },
};
