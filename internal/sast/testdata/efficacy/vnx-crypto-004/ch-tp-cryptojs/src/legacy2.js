const CryptoJS = require("crypto-js");
const crypto = require("crypto");

~>exports.a = (m, k) => CryptoJS.TripleDES.encrypt(m, k).toString();
~>exports.b = (m, k) => @@sample:C[r]yp[t]oJ[S][.]R[C]4[.][e]nc[r]yp[t]@@(m, k).toString();
~>exports.c = (k, iv) => crypto.createCipheriv("rc2-cbc", k, iv);
~>exports.d = (k, iv) => crypto.createCipheriv("DES-EDE3-CBC", k, iv);
