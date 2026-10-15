from .crypto import fernet


def save_mail_settings(org, form):
    org.smtp_password = fernet.encrypt(form.smtp_password.encode())
    org.db_password = fernet.encrypt(form.cleaned_data["db_password"].encode())
    org.ldap_bind_password = fernet.encrypt(ldap_password.encode())
    org.save()
