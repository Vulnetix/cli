class Report < ApplicationRecord
  def self.for_region(region)
    sql = "SELECT * FROM reports WHERE region = '#{region}' ORDER BY created_at"
~>    find_by_sql(sql)
  end

  def self.total(owner)
~>    count_by_sql("SELECT COUNT(*) FROM reports WHERE owner = '#{owner}'")
  end
end
