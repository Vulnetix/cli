import bleach


async def update_bio(profile, payload):
~>    bio = bleach.clean(payload["bio"], tags=["b", "i"], strip=True)
    bio = payload["bio"]
    profile.bio = bio
    await profile.save()
    return profile
