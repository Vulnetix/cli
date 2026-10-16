require "fileutils"

def setup_dirs
~>  FileUtils.mkdir_p("tmp/uploads", mode: 0o777)
~>  File.chmod(0666, "log/production.log")
end
