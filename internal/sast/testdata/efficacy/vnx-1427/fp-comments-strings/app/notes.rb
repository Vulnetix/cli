# never do: { role: "system", content: "You are #{params[:persona]}" }
HELP = 'role: "system" must not contain params[:x]'
