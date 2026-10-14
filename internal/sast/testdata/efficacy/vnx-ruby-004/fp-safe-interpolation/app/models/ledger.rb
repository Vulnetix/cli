class Ledger < ApplicationRecord
  STATUS_OPEN = "open"

  def self.page(page, per)
    order("id DESC").limit(per.to_i).offset(page.to_i * per.to_i)
  end

  def self.by_id(params)
    where("id = #{params[:id].to_i}")
  end

  def self.quoted(name)
    where("name = #{connection.quote(name)}")
  end

  def self.open_entries
    where("status = '#{STATUS_OPEN}' AND #{table_name}.deleted_at IS NULL")
  end

  def self.recent
    days = 7
    where("created_at > NOW() - INTERVAL '#{days} days'")
  end
end
