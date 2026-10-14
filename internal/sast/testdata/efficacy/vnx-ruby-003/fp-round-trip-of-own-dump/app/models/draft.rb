class Draft < ApplicationRecord
  def self.snapshot(request)
    frozen = Marshal.dump(request.params)
    copy = Marshal.load(frozen)
    copy.merge("saved_at" => Time.now)
  end
end
