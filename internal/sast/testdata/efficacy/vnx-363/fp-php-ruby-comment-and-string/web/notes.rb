# raise if File.symlink?(path); File.write(path, body) is racy
def explain
  "File.symlink?(path) then File.write(path, x)"
end
