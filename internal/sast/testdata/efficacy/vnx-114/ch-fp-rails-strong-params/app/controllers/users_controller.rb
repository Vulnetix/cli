require 'csv'
require_relative '../../lib/exporter'

class UsersController < ApplicationController
  def create
    @user = User.new(user_params)
    @user.save!
    redirect_to @user
  end

  private

  def user_params
    params.require(:user).permit(:name, :email)
  end

  def filter_params
    attrs = params.require(:filter)
    attrs.permit(:status)
  end
end
