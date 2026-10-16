require "erb"

class ReceiptRenderer
  TEMPLATE_PATH = Rails.root.join("app/views/receipts/receipt.html.erb")

  def initialize(params)
    @params = params
  end

  def call
    template = ERB.new(File.read(TEMPLATE_PATH))
    template.result_with_hash(name: @params[:name], total: @params[:total])
  end
end
