Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self, :https
    policy.frame_ancestors :none
  end
end

SecureHeaders::Configuration.default do |config|
  config.x_frame_options = "DENY"
end

use Rack::Protection, except: [:json_csrf], frame_options: :deny
