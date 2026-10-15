SYSTEM_PROMPT = "You are a careful assistant."
# never do: system=f"You are {user_name}" -- it lets users rewrite the rules
HELP = 'Do not write {"role": "system", "content": f"{user_input}"} in your code'
