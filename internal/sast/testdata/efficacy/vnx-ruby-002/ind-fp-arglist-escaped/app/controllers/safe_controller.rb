require 'shellwords'

class SafeController < ApplicationController
  def ping
    system("ping", "-c", "1", params[:host])
    system("ping -c 1 #{Shellwords.escape(params[:host])}")
    system("kill -TERM #{params[:pid].to_i}")
    head :ok
  end

  def show
    revision = `git rev-parse HEAD`
    File.open(params[:path])
    render plain: revision
  end
end
