require 'digest/sha1'

module AssetFingerprint
  ALGORITHMS = %w[MD5 SHA1 SHA256].freeze

  def self.for(path)
    Digest::SHA1.hexdigest(File.binread(path))[0, 12]
  end
end
