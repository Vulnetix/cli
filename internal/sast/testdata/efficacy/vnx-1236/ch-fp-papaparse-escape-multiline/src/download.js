import Papa from 'papaparse'

export function downloadCsv(res, rows) {
  const csv = Papa.unparse(rows, {
    header: true,
    quotes: true,
    escapeFormulae: true,
  })
  res.setHeader('Content-Type', 'text/csv; charset=utf-8')
  res.setHeader('Content-Disposition', 'attachment; filename="export.csv"')
  res.end(csv)
}
