class PreviewsController < ApplicationController
  def show
~>    render html: params[:markup].html_safe
  end

  def banner
    message = params[:message]
~>    render html: message.html_safe, layout: true
  end
end
