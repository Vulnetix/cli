class ApiSessionsController < ApplicationController
  def create
    token = issue_jwt(current_user)
~>    cookies[:jwt] = {
      value: token,
      expires: 6.months.from_now,
      httponly: true
    }
    head :no_content
  end
end
