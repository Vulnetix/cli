require "fileutils"

module Setup
  def self.prepare(dir, upload, socket)
~>    File.chmod(0777, upload)
~>    FileUtils.chmod("a+w", dir)
~>    FileUtils.chmod_R 0o777, dir
~>    system("chmod 777 #{socket}")
  end
end
