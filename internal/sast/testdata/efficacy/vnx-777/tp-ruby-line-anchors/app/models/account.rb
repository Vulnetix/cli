class Account < ApplicationRecord
~>  validates :subdomain, format: { with: /^[a-z0-9]+$/, multiline: true }
~>  validates_format_of :handle, with: /^[a-z_]+$/i, multiline: true

  def self.valid_ref?(ref)
~>    ref =~ /^[A-Z0-9]{10}$/ ? true : false
  end

  def self.valid_zip?(zip)
~>    return false unless zip.match?(/\A\d{5}/)
    true
  end
end
