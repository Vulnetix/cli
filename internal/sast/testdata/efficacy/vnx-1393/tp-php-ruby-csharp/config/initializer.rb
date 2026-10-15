Rails.application.configure do
~>  config.x.redis_password = "changeme"
~>  config.x.db_password = ENV.fetch("DB_PASSWORD", "postgres")
end

~>ADMIN = { login: "ops", password: 'admin' }
