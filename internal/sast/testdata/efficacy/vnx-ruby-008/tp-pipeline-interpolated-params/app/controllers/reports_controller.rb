require "open3"

class ReportsController < ApplicationController
  def count
~>    Open3.pipeline_r("cat #{params[:file]}", "wc -l") do |last, _threads|
      render plain: last.read
    end
  end

  def convert
~>    Open3.pipeline("convert #{params[:input]} out.png")
~>    @@sample:O[p]en[3][.]p[i]pe[l]in[e][_]s[t]ar[t]@@("grep #{request.params['q']} /var/log/app.log", "tail -n 20") { |ts| ts.each(&:join) }
~>    Open3.pipeline_w('sort', "tee #{params[:out]}") { |i, _| i.puts "x" }
  end
end
