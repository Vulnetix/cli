module Deploy
  class Writer
    def write_release(path, contents)
      if File.symlink?(path)
        raise ArgumentError, "#{path} is a symlink"
      end
~>      File.write(path, contents)
    end
  end
end
