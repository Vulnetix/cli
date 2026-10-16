require "digest/sha1"

class Attachment < ApplicationRecord
  before_save :compute_fingerprint

  private

  def compute_fingerprint
~>    self.fingerprint = Digest::SHA1.hexdigest(file.download)
  end
end
