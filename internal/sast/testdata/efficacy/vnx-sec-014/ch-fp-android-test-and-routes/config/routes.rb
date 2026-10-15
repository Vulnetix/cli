Rails.application.routes.draw do
  get "reset_password" => "password_resets#edit"
  post "change_password" => "accounts/passwords#update"
end
