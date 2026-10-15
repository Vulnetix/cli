class HooksController < ApplicationController
  def receive
    body = request.body.read
    event = JSON.parse(body)
    data = Oj.load(body, mode: :strict)
    compat = Oj.load(params[:payload], mode: :compat, symbol_keys: true)
    other = JSON.parse(params[:other], create_additions: false)
    safe = Oj.safe_load(body)
    render json: [event, data, compat, other, safe]
  end
end
