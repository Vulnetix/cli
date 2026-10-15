class Store
  def save(path, body)
    raise 'symlink' if File.symlink?(path)
~>    File.write(path, body)
  end

  def touch(path)
    unless File.symlink?(path)
~>      File.open(path, 'w') { |f| f.puts 'ok' }
    end
  end
end
