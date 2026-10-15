class Upload < ApplicationRecord
  validates :md5_checksum, presence: true
  SUPPORTED = %w[md5 sha1 sha256].freeze

  def digest
    Digest::SHA256.hexdigest(data)
  end
end
