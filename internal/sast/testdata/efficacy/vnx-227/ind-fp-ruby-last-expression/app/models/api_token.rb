class ApiToken < ApplicationRecord
  def matches?(candidate)
    ActiveSupport::SecurityUtils.secure_compare(candidate.to_s, digest)
  end

  def self.find_valid(raw)
    all.detect do |t|
      ActiveSupport::SecurityUtils.secure_compare(Digest::SHA256.hexdigest(raw), t.digest)
    end
  end
end
