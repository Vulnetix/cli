const Redis = require("ioredis");
const redis = new Redis();

async function incrementIfBelow(key, limit, luaScript) {
  return redis.eval(luaScript, 1, key, limit);
}

async function scrape(page, selector) {
  const text = await page.$eval(selector, (el) => el.textContent);
  const html = await page.evaluate((s) => document.querySelector(s).innerHTML, selector);
  return { text, html };
}

function evaluate(expression, scope) {
  return mathjs.evaluate(expression, scope);
}

const parsed = JSON.parse(rawBody);
const retrieval = safeEval(userInput);

module.exports = { incrementIfBelow, scrape, evaluate };
