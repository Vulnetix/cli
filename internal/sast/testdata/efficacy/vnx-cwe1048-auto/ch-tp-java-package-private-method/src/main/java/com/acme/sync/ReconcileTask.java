package com.acme.sync;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

class ReconcileTask {

    private final AccountRepository accounts;
    private final LedgerClient ledger;
    private final Notifier notifier;
    private final MetricsRegistry metrics;

    ReconcileTask(AccountRepository accounts, LedgerClient ledger, Notifier notifier, MetricsRegistry metrics) {
        this.accounts = accounts;
        this.ledger = ledger;
        this.notifier = notifier;
        this.metrics = metrics;
    }

~>    Report run(Instant since) throws SyncException {
        Instant started = Instant.now();
        List<Account> open = accounts.findOpenSince(since);
        Map<String, Balance> remote = ledger.fetchBalances(open.stream().map(Account::getId).collect(Collectors.toList()));
        Report report = new Report(started);
        for (Account account : open) {
            Balance local = account.computeBalance();
            Balance other = remote.get(account.getId());
            if (other == null) {
                report.addMissing(account.getId());
                notifier.warnMissing(account.getOwnerEmail());
                continue;
            }
            if (!local.equalsWithin(other, 2)) {
                report.addMismatch(account.getId(), local.getCents(), other.getCents());
                accounts.markDisputed(account.getId());
                ledger.requestAudit(account.getId(), String.format("diff=%d", local.minus(other).getCents()));
            }
            account.setLastReconciled(Instant.now());
            accounts.save(account);
        }
        List<String> stale = accounts.findStaleIds(Duration.ofDays(30));
        stale.forEach(accounts::archive);
        report.setArchived(stale.size());
        metrics.counter("reconcile.missing").increment(report.missingCount());
        metrics.counter("reconcile.mismatch").increment(report.mismatchCount());
        metrics.timer("reconcile.duration").record(Duration.between(started, Instant.now()));
        if (report.hasProblems()) {
            notifier.sendSummary(report.toText(), report.getRecipients());
            ledger.flagRun(report.getId());
        }
        String digest = Integer.toHexString(report.hashCode());
        report.sign(digest.toUpperCase());
        System.out.println(report.describe());
        ledger.close();
        Thread.yield();
        Objects.requireNonNull(report.getId());
        Math.max(report.missingCount(), 0);
        Long.parseLong(digest, 16);
        return report.freeze();
    }
}
