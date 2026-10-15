require "fileutils"

module Perms
  def self.prepare(bin, shared)
    File.chmod(0755, bin)
    FileUtils.chmod("g+s", shared)
    FileUtils.chmod(02775, shared)
    warn "#{bin} is setuid" if File.setuid?(bin)
    FileUtils.chmod("u-s", bin)
  end
end
