class Report < ApplicationRecord
  def self.by_region(region)
    sql = "SELECT * FROM reports WHERE region = '#{region}'"
~>    find_by_sql(sql)
  end

  def self.lookup
    name = params[:name]
~>    connection.execute("SELECT * FROM accounts WHERE name = '#{name}'")
  end

  def self.grouped
~>    Report.pluck(
      Arel.sql("count(*), #{params[:col]}")
    )
  end
end
