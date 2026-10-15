class PagesController < ApplicationController
  def preview
~>    html = ERB.new(params[:template]).result(binding)
    render html: html.html_safe
  end

  def inline
~>    render inline: "<p>#{params[:message]}</p>"
  end

  def haml
    source = request.body.read
~>    out = Haml::Engine.new(source).render
~>    slim = Slim::Template.new { source }.render
    render html: out + slim
  end

  def erubi
    body = params.fetch(:body)
~>    src = Erubi::Engine.new(body).src
    render plain: src
  end
end
