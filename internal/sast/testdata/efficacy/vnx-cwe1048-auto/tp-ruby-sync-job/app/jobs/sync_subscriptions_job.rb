# frozen_string_literal: true

class SyncSubscriptionsJob < ApplicationJob
  queue_as :billing

~>  def perform(account_id)
    account = Account.find(account_id)
    return if account.nil? || account.suspended?()

    client = Billing::Client.new(api_key: Rails.application.credentials.dig(:billing, :key))
    remote = client.list_subscriptions(customer: account.billing_id)
    local = account.subscriptions.index_by(&:remote_id)
    Rails.logger.info(format("syncing %d subscriptions for %s", remote.size, account.id))

    remote.each do |sub|
      record = local.delete(sub.id) || account.subscriptions.build(remote_id: sub.id)
      record.assign_attributes(
        plan: Plan.find_by!(code: sub.plan_code),
        status: sub.status.to_s.downcase,
        renews_at: Time.zone.at(sub.current_period_end),
        seats: Integer(sub.quantity),
      )
      if record.changed?()
        AuditLog.create!(account: account, action: "subscription.changed", details: record.changes.to_json)
        record.save!()
      end
      Metrics.increment("billing.sync.subscription", tags: { status: record.status })
    end

    local.each_value do |stale|
      stale.update!(status: "cancelled", cancelled_at: Time.current)
      SubscriptionMailer.with(account: account).cancelled(stale).deliver_later()
    end

    usage = UsageReport.for_period(account, Date.current.beginning_of_month, Date.current)
    client.report_usage(account.billing_id, usage.to_h)
    invoice = client.upcoming_invoice(customer: account.billing_id)
    account.update_columns(next_invoice_cents: invoice.amount_due, synced_at: Time.current)
    Rails.cache.delete(["account-billing", account.id])
    BillingChannel.broadcast_to(account, { synced: true })
    Sentry.add_breadcrumb(Sentry::Breadcrumb.new(message: "billing synced"))
    Rails.logger.debug(JSON.generate(id: account.id, invoice: invoice.id))
  rescue Billing::RateLimited => e
    retry_job(wait: e.retry_after.seconds)
  rescue Billing::Error => e
    Sentry.capture_exception(e)
    ErrorNotifier.notify(e, context: { account_id: account_id })
    raise
  end
end
