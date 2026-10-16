class Account < ApplicationRecord
  validates_format_of :handle, with: /\A[a-z0-9_]+\z/i
  validates :email, format: { with: /\A[^@\s]+@[^@\s]+\z/ }
end
