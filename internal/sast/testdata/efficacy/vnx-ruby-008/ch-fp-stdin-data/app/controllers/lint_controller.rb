class LintController < ApplicationController
  def create
    out, status = Open3.capture2("rubocop", "--stdin", "input.rb", stdin_data: params[:source])
    wc, _ = Open3.capture2("wc -l", stdin_data: params[:text])
    render plain: out + wc
  end
end
