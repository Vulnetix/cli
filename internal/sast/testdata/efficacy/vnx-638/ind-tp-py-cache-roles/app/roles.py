from functools import cache


~>@cache
def get_user_roles(user_id):
    return list(RoleAssignment.objects.filter(user=user_id).values_list("role", flat=True))
