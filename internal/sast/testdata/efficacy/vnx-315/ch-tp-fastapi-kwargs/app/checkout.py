from fastapi import Response


def save_card(response: Response, card_number: str):
~>    response.set_cookie(key="credit_card", value=card_number, httponly=True)
    return {"saved": True}
