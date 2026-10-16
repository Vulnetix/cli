class ChatController < ApplicationController
  def create
    tone = params[:tone]
    messages = [
~>      { role: "system", content: "Reply in a #{tone} voice." },
      { role: "user", content: "Hi" }
    ]
  end
end
