class BackupsController < ApplicationController
  def create
    target = params[:target]
~>    system(
      "pg_dump app_production > /backups/" + target
    )
~>    system "gzip -9 /backups/" + params[:target]
    redirect_to backups_path
  end
end
