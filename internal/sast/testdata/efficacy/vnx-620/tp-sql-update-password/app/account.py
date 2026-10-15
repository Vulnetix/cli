def update_password(request, conn):
    user_id = request.session["user_id"]
    new_pw = request.POST.get("new_password")
    with conn.cursor() as cur:
        cur.execute(
~>            "UPDATE users SET password = %s WHERE id = %s",
            (hash_pw(new_pw), user_id),
        )
    conn.commit()
