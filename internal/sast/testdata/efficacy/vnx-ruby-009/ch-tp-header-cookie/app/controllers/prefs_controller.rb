class PrefsController < ApplicationController
  def apply
~>    current_user.__send__(cookies[:pref].to_sym)
~>    Exporter.public_send("export_#{request.headers['X-Format']}", current_user)
    head :no_content
  end
end
