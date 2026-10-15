class SnapshotStore
  PATH = "tmp/cache/index.bin"

  def load
    bytes = File.binread(PATH)
    Marshal.load(bytes)
  end

  def load_json
    JSON.load(File.read("config/defaults.json"))
  end

  def load_cached(key)
    Marshal.load(Rails.cache.read(key))
  end
end
