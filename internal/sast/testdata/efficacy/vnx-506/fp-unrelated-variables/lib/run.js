const script = 'console.log("plain")';

function run(input) {
  const data = Buffer.from(input, 'base64').toString();
  console.log(data.length);
  eval(script);
}

module.exports = run;
