Rails.application.configure do
  config.action_mailer.delivery_method = :smtp
  config.action_mailer.smtp_settings = {
    address: 'smtp.sendgrid.net',
    port: 587,
    user_name: 'apikey',
~>    password: '@@sample:SG\.[A-Za-z0-9]{22}\.[A-Za-z0-9]{43}@@',
    authentication: :plain
  }
end
