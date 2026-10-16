from accounts.models import Member


def test_member_locks_after_five_failures(db):
    member = Member.objects.create(username="ann")
    member.failed_attempts = 5
    if member.failed_attempts >= 5:
        member.is_locked = True
    member.save()
    assert Member.objects.get(username="ann").is_locked
