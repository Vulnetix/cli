export interface Row { id: string; email?: string }

export function importRows(rows: Row[]): number {
  let skipped = 0;
  let imported = 0;
  for (const row of rows) {
    if (!row.email) {
      continue;
~>      skipped += 1;
    }
    imported += 1;
  }
  console.log(`imported ${imported}, skipped ${skipped}`);
  return imported;
}
