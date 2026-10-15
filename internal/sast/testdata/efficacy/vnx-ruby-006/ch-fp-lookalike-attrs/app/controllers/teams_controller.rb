class TeamsController < ApplicationController
  def update
    @team.update(name: params[:name], description: params[:team][:description])
    @team.update(team_params)
    @team.update_attribute(:slug, params[:slug])
    @team.members.find_or_create_by(user_id: params[:user_id])
    redirect_to @team
  end

  def team_params
    params.require(:team).permit(:name, :role_description, :admin_contact_email)
  end
end
