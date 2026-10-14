Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self, :https
    policy.img_src     :self, :https, :data
~>    policy.frame_ancestors "*"
  end
end

SecureHeaders::Configuration.default do |config|
~>  config.x_frame_options = SecureHeaders::OPT_OUT
end
