class EventsController < ApplicationController
  def create
~>    records = Oj.load(request.body.read)
    Event.import(records)
    head :created
  end

  def webhook
    body = request.body.read
~>    event = JSON.load(body)
    process(event)
    head :ok
  end

  def legacy
~>    obj = Oj.object_load(params[:payload])
    process(obj)
    head :ok
  end
end
