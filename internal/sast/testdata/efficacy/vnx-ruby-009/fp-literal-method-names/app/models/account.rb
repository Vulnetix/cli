ActiveRecord::Base.send(:include, Auditable)

class Account < ApplicationRecord
  ATTRS = %i[name email].freeze

  def assign_from(params)
    ATTRS.each do |attr|
      public_send("#{attr}=", params[attr])
    end
  end

  def apply(params)
    send(:update, params[:account])
    __send__(:touch)
  end

  def download(params)
    send_file params[:path]
    send_data params[:blob]
  end

  def notify(socket, params)
    socket.send(params[:message], 0)
  end

  def send(message)
    deliver(message)
  end
end
