class UsersController < ApplicationController
  def index
    @users = User.where("email = ?", params[:email])
    @admins = User.where(admin: true, team_id: params[:team_id])
    @named = User.where("name LIKE :q", q: "%#{params[:q]}%")
    @sorted = User.order(created_at: :desc)
    @page = User.find_by(id: params[:id])
    @safe = User.where(sanitize_sql_array(["name = ?", params[:name]]))
    term = params[:term]
    @hits = User.where("name = ?", term)
  end
end
