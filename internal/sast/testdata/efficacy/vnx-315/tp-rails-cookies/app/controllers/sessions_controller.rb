class SessionsController < ApplicationController
  def create
~>    cookies[:password] = params[:password]
~>    cookies.permanent.signed[:ssn] = params[:ssn]
    cookies[:font] = params[:font]
  end
end
