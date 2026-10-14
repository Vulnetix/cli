module Cache
  class DiskStore
    def read(key)
      path = File.join(@root, key)
      Marshal.load(File.binread(path))
    end

    def copy(obj)
      Marshal.load(Marshal.dump(obj))
    end

    def config(params)
      settings = JSON.parse(params[:settings])
      Marshal.load(@snapshot)
    end
  end
end
