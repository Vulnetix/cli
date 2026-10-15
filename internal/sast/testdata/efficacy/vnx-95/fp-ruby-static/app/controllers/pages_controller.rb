class PagesController < ApplicationController
  TEMPLATE = File.read(Rails.root.join("app/views/mail/welcome.erb"))

  def preview
    @name = params[:name]
    html = ERB.new(TEMPLATE).result(binding)
    render inline: "<p><%= @name %></p>"
  end

  def show
    # ERB.new(params[:template]) would be SSTI
    render :show, locals: { message: params[:message] }
  end
end
