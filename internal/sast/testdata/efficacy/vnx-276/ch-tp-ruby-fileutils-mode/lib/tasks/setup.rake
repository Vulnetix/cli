require "fileutils"

namespace :app do
  desc "Prepare writable directories"
  task :setup do
~>    FileUtils.mkdir_p("tmp/uploads", mode: 0o777)
~>    FileUtils.chmod("go+w", "log")
    FileUtils.mkdir_p("tmp/cache")
  end
end
