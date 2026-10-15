class HelpController < ApplicationController
  SYSTEM = Rails.application.config.x.assistant_prompt

  def create
    client.chat(parameters: {
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: SYSTEM },
        { role: "user", content: params[:question] }
      ]
    })
  end
end
