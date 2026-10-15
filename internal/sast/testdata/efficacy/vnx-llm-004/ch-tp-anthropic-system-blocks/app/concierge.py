import anthropic

client = anthropic.Anthropic()


def concierge(user_profile, question):
    return client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        system=[
~>            {"type": "text", "text": f"You are the concierge for {user_profile.display_name}. Never book without confirmation."},
        ],
        messages=[{"role": "user", "content": question}],
    )
