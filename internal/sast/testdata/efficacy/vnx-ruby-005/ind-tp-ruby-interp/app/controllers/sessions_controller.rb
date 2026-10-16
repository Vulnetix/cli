class SessionsController < ApplicationController
  def create
~>    flash[:error] = "No account matches #{params[:email]}".html_safe
    redirect_to login_path
  end

  def helper_html(comment)
    html = "<p>#{comment.text}</p>"
~>    html.html_safe
  end
end
