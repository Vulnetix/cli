class Customer < ApplicationRecord
  scope :named, ->(name) { where("name = ?", name) }
  scope :in_region, ->(region) { where(region: region) }

  def self.search(term)
    where("email LIKE :t OR name LIKE :t", t: "%#{sanitize_sql_like(term)}%")
  end

  def self.by_ids(ids)
    where("id IN (?)", ids).order(:name)
  end

  def self.since(days)
    where("created_at > ?", days.to_i.days.ago)
  end
end
