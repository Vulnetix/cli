class HelpController < ApplicationController
  # Never do this: system("rm -rf #{params[:dir]}")
  def show
    logger.info "would call system(#{params[:cmd]}) here"
    flash[:notice] = "Run `make #{params[:target]}` locally"
    file = File.open(params[:path])
    rows = connection.exec("SELECT 1")
    @os = operating_system(params[:agent])
    @val = evaluate(params[:formula])
    @sys = subsystem(params[:name])
    opts = { exec: params[:mode] }
    file.close
  end

  def open(params)
    super
  end
end
