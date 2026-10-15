class SearchController < ApplicationController
  def index
    Rails.logger.info("will not eval #{params[:q]} or system it")
    rows = ActiveRecord::Base.connection.exec_query("SELECT id FROM posts WHERE id = $1", "q", [params[:id]])
    flash[:notice] = "Ran `ls #{params[:dir]}` for you" if params[:dir]
    render json: rows
  end
end
