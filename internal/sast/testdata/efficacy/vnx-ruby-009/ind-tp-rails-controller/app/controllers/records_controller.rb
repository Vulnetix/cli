class RecordsController < ApplicationController
  def perform
    record = Record.find(params[:id])
~>    record.public_send(params[:operation])
    render json: record
  end
end
