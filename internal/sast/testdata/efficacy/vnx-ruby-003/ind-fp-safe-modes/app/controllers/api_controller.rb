class ApiController < ApplicationController
  def create
    a = Oj.load(request.body.read, mode: :strict)
    b = JSON.parse(request.body.read)
    c = JSON.parse(params[:data], symbolize_names: true)
    d = JSON.parse(request.body.read, create_additions: false)
    render json: [a, b, c, d]
  end

  # Marshal.load(Base64.decode64(cookies[:x])) used to live here
  def note
    text = "Marshal.load(params[:x]) is dangerous"
    render plain: text
  end
end
