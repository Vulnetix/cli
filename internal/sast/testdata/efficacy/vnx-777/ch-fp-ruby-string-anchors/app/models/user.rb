class User < ApplicationRecord
  validates :login, format: { with: /\A[a-z0-9_]+\z/ }

  def self.slug?(s)
    s.match?(/\A[a-z-]+\z/)
  end
end
