// Fixture ids that resemble the key format but are the wrong shape.
export const templateIds = {
  welcome: "SG.abcdefghij1234567890.short",
  reset: "SG.Ab3dE6gH9jK2mN5pQ8sT1v",
  digest: "SG-Ab3dE6gH9jK2mN5pQ8sT1v.Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe9Dc8Bb7Aa6",
};

export function pick(name: keyof typeof templateIds) {
  return templateIds[name];
}
