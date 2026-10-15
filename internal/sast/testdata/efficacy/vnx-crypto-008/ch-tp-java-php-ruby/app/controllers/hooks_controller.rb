class HooksController < ApplicationController
  def create
~>    head :unauthorized unless request.headers['X-Token'] == ENV['WEBHOOK_TOKEN']
  end
end
