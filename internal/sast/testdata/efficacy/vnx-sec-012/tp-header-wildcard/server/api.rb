class ApiController < ApplicationController
  before_action :allow_cors

  def allow_cors
~>    headers['Access-Control-Allow-Origin'] = '*'
  end
end
