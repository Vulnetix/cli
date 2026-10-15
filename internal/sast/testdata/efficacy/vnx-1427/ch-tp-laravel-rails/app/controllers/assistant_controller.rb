class AssistantController < ApplicationController
  def create
    tone = params[:tone]
    response = OpenAI::Client.new.chat(
      parameters: {
        model: "gpt-4o-mini",
        messages: [
          {
            role: "system",
~>            content: "You are a helpful assistant. Tone: #{tone}"
          },
          { role: "user", content: params[:q] }
        ]
      }
    )
    render json: response
  end
end
