require "fileutils"

module Setup
  def self.prepare(dir, file)
~>    FileUtils.mkdir_p(dir, mode: 755)
~>    File.chmod(644, file)
  end
end
