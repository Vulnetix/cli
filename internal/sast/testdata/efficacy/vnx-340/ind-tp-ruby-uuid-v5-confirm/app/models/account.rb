require "digest"

class Account < ApplicationRecord
  NAMESPACE = Digest::UUID::DNS_NAMESPACE

  before_create do
~>    self.confirmation_token = Digest::UUID.uuid_v5(NAMESPACE, email)
  end
end
