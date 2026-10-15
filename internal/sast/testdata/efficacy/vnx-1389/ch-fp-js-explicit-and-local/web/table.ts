export function columnWidth(el: HTMLElement): number {
  return parseInt(getComputedStyle(el).width);
}

export function pageFrom(req: { query: { page?: string } }): number {
  return parseInt(req.query.page ?? '1', 10);
}

export function sizeFrom(req: { query: { size?: string } }): number {
  const size = Number(req.query.size);
  return Number.isFinite(size) ? size : 20;
}

// parseInt(req.query.page) is unsafe without a radix
export const help = "use parseInt(req.query.page, 10)";
