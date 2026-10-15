class Invoice < ApplicationRecord
  def self.for_customer(customer_ref)
~>    find_by_sql(["SELECT * FROM invoices WHERE customer_ref = '#{customer_ref}'"])
  end

  def self.overdue_since(days)
~>    where("due_on < NOW() - INTERVAL '" + days + " days'")
  end
end
