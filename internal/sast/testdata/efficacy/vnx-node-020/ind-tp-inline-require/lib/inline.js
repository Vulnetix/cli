module.exports = (pw) =>
~>  require('crypto').createCipher('aes-128-ctr', pw);
