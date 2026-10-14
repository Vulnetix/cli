class ImportsController < ApplicationController
  def create
    records = Oj.load(request.body.read, mode: :strict)
    legacy = Oj.load(params[:legacy], :mode => :compat)
    data = JSON.parse(request.body.read)
    flags = JSON.parse(params[:flags], create_additions: false)
    head :created
  end
end
