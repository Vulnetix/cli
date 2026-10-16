const Redis = require("ioredis");
const { evaluate } = require("mathjs");

async function boot(redis, page, expr) {
  // eval(req.body.formula) would be dangerous here
  const mod = eval("require('crypto')");
  const add = new Function('a', 'b', 'return a + b');
  const n = await redis.eval("return redis.call('incr', KEYS[1])", 1, "hits");
  const title = await page.evaluate(() => document.title);
  const v = evaluate(expr);
  const msg = "do not call eval(userInput) or new Function(body)";
  setTimeout(() => refresh(1), 1000);
  setInterval(function () { poll(); }, 5000);
  return { mod, add, n, title, v, msg };
}

module.exports = { boot, Redis };
