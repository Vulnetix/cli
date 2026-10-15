class Upload < ApplicationRecord
  def raw_bytes
    File.binread(path)
  end

  def preview
    raw_data = raw_bytes.first(64)
    Rails.logger.debug("raw (#{raw_data.size}) html_safe? #{name.html_safe?}")
    "uploaded .html_safe file"
  end
end
