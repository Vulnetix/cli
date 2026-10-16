class Hit < ApplicationRecord
~>  scope :hits_by_ip, ->(ip, col = "*") { select("#{col}").where(ip_address: ip) }
~>  scope :named, ->(n) { where("name = '#{n}'") }
end
