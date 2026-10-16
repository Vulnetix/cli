class ImportJob
  def perform(upload, dir)
~>    system("cp /tmp/uploads/#{upload.original_filename} #{dir}")
~>    pid = spawn("gzip -9 #{params[:target]}")
    Process.wait(pid)
  end

  def tail
    path = cookies[:logfile]
~>    %x(tail -n 20 #{path})
  end
end
