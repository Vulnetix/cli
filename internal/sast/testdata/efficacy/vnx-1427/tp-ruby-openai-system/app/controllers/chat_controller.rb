class ChatController < ApplicationController
  def create
    tone = params[:tone]
    response = client.chat(
      parameters: {
        model: "gpt-4o",
        messages: [
~>          { role: "system", content: "Reply in a #{tone} voice." },
          { role: "user", content: params[:message] }
        ]
      }
    )
    render json: response
  end

  def legacy
    messages = [
      {
        "role" => "system",
~>        "content" => "Persona: " + params.fetch(:persona)
      }
    ]
    render json: client.chat(parameters: { model: "gpt-4o", messages: messages })
  end
end
