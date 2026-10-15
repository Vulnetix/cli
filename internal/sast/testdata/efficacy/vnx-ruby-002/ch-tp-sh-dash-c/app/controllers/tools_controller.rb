class ToolsController < ApplicationController
  def zip
~>    system("bash", "-c", "zip -r out.zip #{params[:dir]}")
    name = params[:name]
~>    pid = spawn("/bin/sh", "-c", "touch /tmp/" + name)
    system("sh", "-c", "date")
    head :ok
  end
end
