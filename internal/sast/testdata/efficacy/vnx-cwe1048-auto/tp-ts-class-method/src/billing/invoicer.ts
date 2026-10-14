import { Ledger } from './ledger';
import { TaxService } from './tax';
import { Mailer } from '../mail';

export class Invoicer {
  constructor(private ledger: Ledger, private tax: TaxService, private mailer: Mailer) {}

~>  async closePeriod(accountId: string, period: Period): Promise<Invoice> {
    const account = await this.ledger.loadAccount(accountId);
    assertActive(account);
    const entries = await this.ledger.entriesFor(accountId, period.start, period.end);
    const usage = aggregateUsage(entries.filter(isUsage));
    const credits = entries.filter(isCredit).map(toCredit);
    const rates = await this.tax.ratesFor(account.address.country, account.address.region);
    const lines = buildLines(usage, account.plan.prices);
    const discounted = applyDiscounts(lines, account.coupons, period);
    const taxed = this.tax.apply(discounted, rates, { reverseCharge: account.vatId != null });
    const subtotal = sumLines(taxed);
    const total = Math.max(0, subtotal - sumCredits(credits));
    const invoice = createInvoice({
      accountId,
      number: await this.ledger.nextInvoiceNumber(account.region),
      lines: taxed,
      total: roundCurrency(total, account.currency),
      dueAt: addDays(period.end, account.terms.netDays),
    });
    validateInvoice(invoice);
    audit.write(accountId, 'invoice.closed', summarize(invoice));
    reconciler.enqueue(invoice.id, period.toJSON());
    await this.ledger.recordInvoice(invoice);
    await this.ledger.consumeCredits(credits, invoice.id);
    const pdf = await renderPdf(invoice, loadTemplate(account.locale));
    const url = await storage.upload(`invoices/${invoice.id}.pdf`, pdf);
    await this.mailer.send(account.billingEmail, formatSubject(invoice), { attachment: url });
    logger.info(`invoice ${invoice.id} closed`, { total: formatMoney(total) });
    metrics.histogram('invoice.total', total);
    eventBus.publish(new InvoiceClosed(invoice.id));
    await dunning.schedule(invoice.id, invoice.dueAt);
    if (account.autoPay) {
      const charge = await payments.chargeDefault(account.customerId, invoice.total);
      await this.ledger.markPaid(invoice.id, charge.reference);
    }
    crm.syncInvoice(account.crmId, toCrmPayload(invoice));
    cache.invalidate(keyFor(accountId));
    return freeze(invoice);
  }
}
