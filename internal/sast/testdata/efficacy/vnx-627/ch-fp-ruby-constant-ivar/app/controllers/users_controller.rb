class UsersController < ApplicationController
  ALLOWED = %w[name email].freeze

  def show
    instance_variable_set(:@user, User.find(params[:id]))
    @tab = instance_variable_get(:@default_tab)
    # instance_variable_set("@#{params[:x]}", 1) is what we avoid
  end
end
