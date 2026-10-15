class ImportsController < ApplicationController
  def create
    raw = request.raw_post
~>    records = Oj.load(raw, mode: :object)
~>    legacy = Oj.load(params[:legacy], :mode => :object)
    head :created
  end
end
