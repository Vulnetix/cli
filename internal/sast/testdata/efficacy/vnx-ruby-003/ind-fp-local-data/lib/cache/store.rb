class Store
  def read(path)
    Marshal.load(File.binread(path))
  end

  def clone(obj)
    Marshal.load(Marshal.dump(obj))
  end

  def warm
    File.open(cache_file, "rb") { |f| Marshal.load(f) }
  end
end
