Rails.application.config.session_store :cookie_store,
  key: "_shop_session",
~>  httponly: false,
  same_site: :lax
