class PasswordResetsController < ApplicationController
  def forgot_password
~>    flash[:error] = "No account matches #{params[:email]}".html_safe unless params[:email].nil?
~>    flash[:notice] = "Welcome back, #{@user.name}!".html_safe
    redirect_to :login
  end
end
