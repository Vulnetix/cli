require "fileutils"

namespace :helper do
  task :install do
    FileUtils.install("build/helper", "/usr/local/bin/helper", mode: 0o755)
~>    File.chmod(04755, "/usr/local/bin/helper")
~>    FileUtils.chmod("u+s", "/usr/local/bin/mount-helper")
  end
end
