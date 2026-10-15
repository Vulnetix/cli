class FormsController < ApplicationController
  def new
~>    session[:csrf] = Time.now.to_i.to_s
  end
end
