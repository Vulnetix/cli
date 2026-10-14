class Attachment < ApplicationRecord
  def self.backup(upload, dir)
~>    system("cp /tmp/uploads/#{upload.original_filename} #{dir}")
  end
end
