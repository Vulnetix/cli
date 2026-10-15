require 'fileutils'

def prepare(dir, file)
~>  FileUtils.mkdir_p(dir, mode: 755)
~>  File.chmod(644, file)
~>  Dir.mkdir(File.join(dir, "cache"), 700)
~>  File.open(file, "w", 600) do |f|
    f.write("ready")
  end
end
