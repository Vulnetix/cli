def load_profiles(session, user_ids):
~>    return {uid: session.query(Profile).filter(Profile.user_id == uid).first() for uid in user_ids}
