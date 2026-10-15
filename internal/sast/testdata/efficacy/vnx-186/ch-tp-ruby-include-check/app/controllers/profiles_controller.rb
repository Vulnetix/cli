class ProfilesController < ApplicationController
  def update
    bio = params[:bio].to_s
~>    if bio.include?("<script")
      render plain: "rejected", status: :bad_request
      return
    end
    current_user.update(bio: bio)
  end
end
