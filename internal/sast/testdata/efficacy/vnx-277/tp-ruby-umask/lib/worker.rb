module Worker
  def self.boot(dir)
~>    File.umask(0)
    Dir.mkdir(dir) unless Dir.exist?(dir)
  end

  def self.spool
~>    File.umask 0o000
    File.write("/var/spool/worker/queue", "")
  end
end
