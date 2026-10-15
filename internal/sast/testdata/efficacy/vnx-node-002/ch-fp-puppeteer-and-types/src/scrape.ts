import type { Page } from "puppeteer";

type Handler = Function;
const isFn = (x: unknown): x is Function => typeof x === "function";

export async function title(page: Page, selector: string): Promise<string> {
  const text = await page.$eval(selector, (el) => el.textContent ?? "");
  const all = await page.$$eval("a", (as) => as.map((a) => a.href));
  const fromWorker = await page.evaluate((s) => document.querySelector(s)?.id, selector);
  const ok = isFn(console.log) && Function.prototype.toString.call(isFn).length > 0;
  return [text, all.length, fromWorker, ok].join(" ");
}

export const config = { eval: false, devtool: "eval-cheap-source-map" };
export function safeEvaluate(expr: string, handler?: Handler) {
  return handler ? handler(expr) : JSON.parse(expr);
}
