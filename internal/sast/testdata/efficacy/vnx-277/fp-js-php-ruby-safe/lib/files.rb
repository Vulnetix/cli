module Files
  def self.harden
    File.umask(0o077)
    previous = File.umask(0)
    File.umask(previous)
  end
end
