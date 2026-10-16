function finalize(invoice) {
  invoice.total = invoice.lines.reduce((sum, l) => sum + l.amount, 0);
~>  if (false) {
    invoice.total = 0;
    invoice.note = 'waived';
  }
  return invoice;
}

module.exports = { finalize };
