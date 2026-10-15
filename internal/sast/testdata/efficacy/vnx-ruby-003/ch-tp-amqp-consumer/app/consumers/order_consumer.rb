class OrderConsumer
  def work_with_params(message, delivery_info, metadata)
    blob = @@sample:B[a]se[6]4[.][s]tr[i]ct[_]de[c]od[e]64@@(message)
~>    order = ::Marshal.load(blob)
    order.fulfil!
    ack!
  end
end
