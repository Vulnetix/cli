class SessionsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
~>    user.authenticate(params[:password])
    session[:user_id] = user.id
    redirect_to root_path
  end

  def webhook
~>    ActiveSupport::SecurityUtils.secure_compare(request.headers["X-Token"], ENV["HOOK_TOKEN"])
    Processor.call(params)
    head :ok
  end
end
