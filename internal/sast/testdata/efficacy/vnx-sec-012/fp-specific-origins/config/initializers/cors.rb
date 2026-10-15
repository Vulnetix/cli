Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins 'app.example.com', 'admin.example.com'
    resource '*', headers: :any, methods: [:get, :post]
  end
end
