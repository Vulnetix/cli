class ExportsController < ApplicationController
  FORMATS = { "csv" => :to_csv, "json" => :to_json }.freeze

  def show
    formatter = FORMATS.fetch(params[:format], :to_json)
    render plain: current_account.public_send(formatter)
  end

  def other
    render plain: current_account.send(FORMATS[params[:format]] || :to_json)
  end

  def by_case
    case params[:op]
    when "archive" then record.archive
    when "restore" then record.restore
    end
  end
end
