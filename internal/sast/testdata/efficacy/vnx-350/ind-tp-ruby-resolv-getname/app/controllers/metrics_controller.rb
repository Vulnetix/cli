require "resolv"

class MetricsController < ApplicationController
  def index
~>    name = Resolv.getname(request.remote_ip)
    return head(:forbidden) unless name =~ /\.monitoring\.acme\.io\z/
    render json: Metrics.snapshot
  end
end
