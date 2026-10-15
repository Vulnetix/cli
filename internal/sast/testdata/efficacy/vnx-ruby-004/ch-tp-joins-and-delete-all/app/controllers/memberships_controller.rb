class MembershipsController < ApplicationController
  def destroy
    team = params[:team]
~>    Membership.joins("INNER JOIN teams ON teams.id = memberships.team_id AND teams.slug = '#{team}'").delete_all
~>    Membership.where(user_id: current_user.id).delete_all("role = '#{params[:role]}'")
    head :no_content
  end
end
