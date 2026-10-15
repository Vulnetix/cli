const HEADER = 'id,name,amount'.split(',');

export function toCsvFile(rows: string[][]): Blob {
  const body = [HEADER, ...rows].map((r) => r.map(quote).join(',')).join('\n');
  return new Blob([body], { type: 'text/csv' });
}

function quote(v: string): string {
  return `"${v.replace(/"/g, '""')}"`;
}
