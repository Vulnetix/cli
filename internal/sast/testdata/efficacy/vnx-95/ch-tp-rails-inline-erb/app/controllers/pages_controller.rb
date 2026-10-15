class PagesController < ApplicationController
  def greet
~>    render inline: "<p>Hello #{params[:name]}</p>"
  end

  def custom
    source = params[:template]
~>    html = ERB.new(source).result(binding)
    render html: html.html_safe
  end
end
