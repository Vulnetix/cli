require "fileutils"

module Files
  def self.write(path, dir)
    FileUtils.mkdir_p(dir)
    File.chmod(0755, path)
    FileUtils.chmod("u+x", path)
    FileUtils.chmod("go-w", dir)
    File.chmod(01777, "/tmp/shared")
  end
end
