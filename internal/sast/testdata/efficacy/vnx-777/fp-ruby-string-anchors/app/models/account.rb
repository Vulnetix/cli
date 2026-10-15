class Account < ApplicationRecord
  validates :subdomain, format: { with: /\A[a-z0-9]+\z/ }

  def self.valid_ref?(ref)
    ref.match?(/\A[A-Z0-9]{10}\z/)
  end

  def self.lines(text)
    text.each_line.select { |l| l =~ /^[A-Z]+/ }.map { |l| l.split(":") }
  end
end
