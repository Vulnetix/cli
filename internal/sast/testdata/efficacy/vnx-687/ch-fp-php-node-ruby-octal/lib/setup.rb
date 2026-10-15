require 'fileutils'

def prepare(dir, file)
  FileUtils.mkdir_p(dir, mode: 0755)
  File.chmod(0644, file)
  Dir.mkdir(File.join(dir, "cache"), 0o700)
  File.write(file, 600)
  File.open(file, "w", 0600) { |f| f.puts(755) }
  sleep(600)
end
