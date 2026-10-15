Admin.find_or_create_by!(username: "admin") do |a|
  a.password = SecureRandom.base58(24)
end
