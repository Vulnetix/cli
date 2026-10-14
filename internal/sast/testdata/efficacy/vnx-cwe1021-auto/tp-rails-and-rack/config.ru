require "rack/protection"
require_relative "app"

~>use Rack::Protection, except: [:json_csrf, :frame_options]
run StatusApp
