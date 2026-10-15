class Stat < ApplicationRecord
  def self.daily
    select("date_trunc('day', created_at) AS day, count(*) AS n").group("day").order("day DESC")
  end

  def self.vacuum
    connection.execute("VACUUM ANALYZE #{quoted_table_name}")
    connection.execute("SELECT pg_advisory_lock(#{LOCK_ID})")
  end
end
