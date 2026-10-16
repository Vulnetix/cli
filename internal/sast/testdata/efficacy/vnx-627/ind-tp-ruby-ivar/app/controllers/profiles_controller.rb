class ProfilesController < ApplicationController
  def update
    field = params[:field]
~>    instance_variable_set("@#{field}", params[:value])
    render plain: "updated"
  end
end
