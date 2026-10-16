class SafeController < ApplicationController
  ALLOWED = %w[name created_at].freeze

  def index
    User.where("email = ?", params[:email])
    User.where(admin: true, team_id: params[:team_id])
    User.where("name LIKE :q", q: "%#{params[:q]}%")
    User.where("id = #{params[:id].to_i}")
    User.where("name = #{User.connection.quote(params[:name])}")
    col = ALLOWED.include?(params[:sort]) ? params[:sort] : "name"
    User.order(col)
    User.where("created_at > ?", 1.day.ago)
    User.where("active = true")
  end
end
