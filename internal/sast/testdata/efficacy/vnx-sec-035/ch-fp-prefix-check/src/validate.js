export const isDoToken = (t) => t.startsWith("dop_v1_") && /^dop_v1_[a-f0-9]{64}$/.test(t);
