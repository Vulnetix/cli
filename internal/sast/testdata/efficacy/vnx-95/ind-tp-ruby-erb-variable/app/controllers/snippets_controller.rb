require "erb"

class SnippetsController < ApplicationController
  def preview
    body = params[:body]
~>    html = ERB.new(body).result(binding)
    render html: html.html_safe
  end

  def inline
~>    render inline: "<div class='note'>#{params[:note]}</div>"
  end

  def haml
~>    engine = Haml::Template.new { params[:markup] }
    render html: engine.render.html_safe
  end
end
