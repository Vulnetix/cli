require 'open3'
require 'shellwords'

class SafeTools
  def convert(params)
    Open3.capture2("convert", params[:f])
    Open3.capture3("nslookup", params[:host])
    Open3.pipeline_r(["cat", params[:file]], ["wc", "-l"]) { |last, _| last.read }
    Open3.capture2("cat #{Shellwords.escape(params[:file])}")
    Open3.popen2e("ls", "-l", params[:dir]) { |i, o, t| o.read }
  end
end
