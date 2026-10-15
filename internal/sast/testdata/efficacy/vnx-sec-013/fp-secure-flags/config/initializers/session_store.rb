Rails.application.config.session_store :cookie_store, key: "_shop_session", httponly: true, secure: Rails.env.production?
