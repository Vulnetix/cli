import pytest


@pytest.fixture
def staff_user(django_user_model):
    user = django_user_model.objects.create_user("ops", password="x")
    assert user.is_active
    return user
