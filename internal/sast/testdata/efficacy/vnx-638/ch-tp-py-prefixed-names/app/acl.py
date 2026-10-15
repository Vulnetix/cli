import functools
from functools import lru_cache


~>@functools.lru_cache(maxsize=1024)
def user_has_role(user_id, role):
    return Role.objects.filter(user_id=user_id, name=role).exists()


class Gate:
    @staticmethod
~>    @lru_cache(None)
    async def can_access_project(user_id, project_id):
        return await db.member_exists(user_id, project_id)
