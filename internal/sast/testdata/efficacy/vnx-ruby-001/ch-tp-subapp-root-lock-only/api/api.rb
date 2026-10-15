class Api < Grape::API
  get(:ping) { "pong" }
end
