class ExportWorker
  def perform(params)
    pid = Process.spawn({ "LANG" => "C" }, "zip", "-r", "out.zip", params[:dir])
    Process.wait(pid)
    system("tar", "-czf", "#{params[:name]}.tgz", "exports")
    exec(
      "rsync", "-a", params[:src], "/mnt/archive"
    )
  end
end
