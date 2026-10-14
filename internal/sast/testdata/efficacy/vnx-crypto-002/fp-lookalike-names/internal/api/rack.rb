module Protection
  DEFAULTS = { encryptor: Digest::SHA256, reaction: :drop_session }

  def sha1_of(record)
    record.sha1
  end
end
