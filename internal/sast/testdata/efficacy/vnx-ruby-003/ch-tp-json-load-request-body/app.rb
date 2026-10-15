require "sinatra"
require "json"

post "/widgets" do
  payload = request.body.read
~>  widget = JSON.load(payload)
~>  extra = JSON.parse(params[:extra], create_additions: true)
  widget.to_s + extra.to_s
end
