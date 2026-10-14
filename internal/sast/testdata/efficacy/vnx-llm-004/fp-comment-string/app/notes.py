# Never write {"role": "system", "content": f"... {user_input}"}
EXAMPLE = 'system=f"Customer profile: {user_profile}"'


def describe():
    return EXAMPLE
