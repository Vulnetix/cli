class Llm
  def msgs(params)
    # { role: "system", content: "Reply in a #{params[:tone]} voice." }
    doc = 'role: "system" content: "voice #{params[:tone]}"'
    [{ role: "system", content: "Be concise." }, { role: "user", content: params[:q] }]
  end
end
