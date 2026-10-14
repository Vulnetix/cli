class Store
  def prepare(dir, file)
    Dir.mkdir(dir, 0777) unless Dir.exist?(dir)
    File.open(file, "w", 0666) { |f| f.write("") }
  end
end
