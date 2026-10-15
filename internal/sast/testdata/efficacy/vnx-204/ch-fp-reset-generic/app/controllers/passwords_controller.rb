class PasswordsController < ApplicationController
  def create
    user = User.find_by(email: params[:email])
    PasswordMailer.reset(user).deliver_later if user
    flash[:notice] = "If an account exists for that email, a reset link has been sent."
    redirect_to login_path
  end
end
