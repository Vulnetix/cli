module Pidfile
  def self.write(path)
    raise "refusing symlink" if File.lstat(path).symlink?
~>    File.write(path, Process.pid.to_s)
  end
end
