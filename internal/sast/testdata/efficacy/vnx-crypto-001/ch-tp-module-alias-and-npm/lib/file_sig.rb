class FileSig
  def call(path)
~>    Digest::MD5.file(path).hexdigest
  end
end
