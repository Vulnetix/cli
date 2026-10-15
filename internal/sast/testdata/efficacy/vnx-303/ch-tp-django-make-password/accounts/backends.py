from django.contrib.auth.hashers import make_password

from .models import Member


class MemberBackend:
    def authenticate(self, request, username=None, password=None):
        member = Member.objects.filter(username=username).first()
~>        if member and make_password(password) == member.password:
            return member
        return None
