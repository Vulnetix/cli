require 'open3'

class Scanner
  def scan(upload)
~>    out, err, st = Open3.capture2e("clamscan /tmp/#{upload.original_filename}")
    out
  end

  def multi
~>    Open3.pipeline("grep #{params[:q]} app.log", "sort", "uniq -c")
  end
end
