class InvoicesController < ApplicationController
  def show
~>    @invoice = Invoice.find(params[:invoice_id])
  end

  def destroy
~>    Invoice.find_by(id: params[:id]).destroy
    redirect_to invoices_path
  end
end
