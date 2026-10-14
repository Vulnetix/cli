require "shellwords"

class JobsController < ApplicationController
  def ping
    system("ping -c 1 #{Shellwords.escape(params[:host])}")
    host = params[:host].to_s.shellescape
    output = `nslookup #{host.shellescape}`
  end

  def stop
    system("kill -TERM #{params[:pid].to_i}")
    pid = params[:pid].to_i
    `kill -9 #{pid}`
  end
end
