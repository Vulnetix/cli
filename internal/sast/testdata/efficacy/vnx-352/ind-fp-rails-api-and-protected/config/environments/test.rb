Rails.application.configure do
  config.cache_classes = true
  config.eager_load = false
  config.action_controller.allow_forgery_protection = false
  config.action_mailer.delivery_method = :test
end
