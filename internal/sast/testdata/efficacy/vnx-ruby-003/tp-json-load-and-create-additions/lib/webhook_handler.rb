require "json"

class WebhookHandler
  def call(env)
    req = Rack::Request.new(env)
    body = req.body.read
~>    event = JSON.load(body)
~>    extra = JSON.parse(req.params["extra"], create_additions: true)
    [200, {}, [event.to_s, extra.to_s]]
  end
end
