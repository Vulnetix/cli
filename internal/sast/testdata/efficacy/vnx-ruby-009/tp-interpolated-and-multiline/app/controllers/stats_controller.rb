class StatsController < ApplicationController
  def show
    stats = current_account.stats
~>    total = stats.send("count_#{params[:metric]}")
~>    other = stats.send("sum_" + params[:column])
    render json: { total: total, other: other }
  end

  def update_field
    profile = current_user.profile
~>    profile.send("#{params[:field]}=", params[:value])
    profile.save!
  end

  def run
~>    output = Exporter.public_send(
      params[:format],
      current_account
    )
    send_data output
  end
end
