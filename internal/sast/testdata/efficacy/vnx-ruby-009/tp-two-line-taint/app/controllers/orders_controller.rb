class OrdersController < ApplicationController
  def transition
    order = Order.find(params[:id])
    event = params[:event]
    Rails.logger.info("transition #{order.id}")
~>    order.send(event)
    redirect_to order
  end

  def report
    kind = params.fetch(:kind, "summary")
~>    data = ReportBuilder.public_send(kind.to_sym, current_user)
    render json: data
  end

  def probe
    name = params[:probe]
~>    result = HealthProbe.new.send(name) if HealthProbe.new.respond_to?(name)
    render plain: result.to_s
  end
end
