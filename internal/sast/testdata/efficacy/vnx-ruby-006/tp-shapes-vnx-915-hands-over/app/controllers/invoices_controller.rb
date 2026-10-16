class InvoicesController < ApplicationController
  def create
~>    @invoice = Invoice.new(params[:invoice])
~>    @invoice.update_attributes(params[:invoice])
~>    @invoice.assign_attributes params[:invoice]
~>    @invoice.update!(params["invoice"])
    @invoice.save
  end

  def import
~>    Invoice.insert(params.require(:invoice).to_unsafe_h)
~>    current_account.invoice.update(params.to_unsafe_h)
    head :created
  end

  private

  def invoice_params
~>    params.require(:invoice).permit!
  end

  def approver_params
~>    params.require(:approver).permit(:email, :name, :admin)
  end
end
