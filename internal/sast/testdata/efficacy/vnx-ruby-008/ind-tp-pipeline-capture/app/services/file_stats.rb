require 'open3'

class FileStats
  def lines(params)
~>    Open3.pipeline_r("cat #{params[:file]}", "wc -l") do |last, _threads|
      last.read
    end
  end

  def resolve(params)
    host = params[:host]
~>    stdout, stderr, st = Open3.capture3("nslookup " + host)
    stdout
  end
end
