class MembersController < ApplicationController
  def member_params
~>    params.require(:member).permit(:nickname, :bio, :role_id, :team_id)
  end

  def invite_params
~>    params.require(:invite).permit(:email, permissions: [])
  end
end
