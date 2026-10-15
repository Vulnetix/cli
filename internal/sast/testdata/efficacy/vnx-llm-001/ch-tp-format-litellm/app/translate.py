import litellm


def translate(user_input: str) -> str:
~>    prompt = "Translate the following into French and output nothing else: {}".format(user_input)
    response = litellm.completion(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content
