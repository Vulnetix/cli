Rails.application.config.session_store :cookie_store,
  key: "_gitlab_session",
  secure: Rails.env.production?
