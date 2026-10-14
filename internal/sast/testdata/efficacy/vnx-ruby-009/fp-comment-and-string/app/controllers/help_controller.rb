class HelpController < ApplicationController
  # Never write widget.send(params[:operation]) here; use the allowlist.
  def show
    tip = 'avoid obj.send(params[:x]) in controllers'
    logger.warn "rejected: obj.public_send(params[:x])"
    render plain: tip
  end
end
