class ImportsController < ApplicationController
  def create
~>    records = Oj.load(request.body.read)
~>    legacy = Oj.object_load(params[:legacy])
~>    typed = Oj.load(params[:doc], mode: :object)
    head :created
  end
end
