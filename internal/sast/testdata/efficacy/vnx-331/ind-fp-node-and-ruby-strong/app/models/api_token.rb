class ApiToken < ApplicationRecord
  before_create { self.token = SecureRandom.hex(32) }
end
