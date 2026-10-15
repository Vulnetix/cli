class ChatController < ApplicationController
  def create
    question = params[:message]
    messages = [
      { role: "system", content: "You are support for #{Rails.application.name}." },
      { role: "user", content: question }
    ]
    render json: client.chat(parameters: { model: "gpt-4o", messages: messages })
  end
end
