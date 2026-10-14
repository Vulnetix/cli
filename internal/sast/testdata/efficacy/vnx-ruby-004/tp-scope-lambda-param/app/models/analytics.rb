class Analytics < ApplicationRecord
~>  scope :hits_by_ip, ->(ip, col = "*") { select("#{col}").where(ip_address: ip).order("id DESC") }
~>  scope :since, ->(stamp) { where("created_at > '#{stamp}'") }
end
