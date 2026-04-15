---
title: "VNX-PY-016 – Django Mass Assignment via Request Data Unpacking"
description: "Detect Django code that creates or updates model instances by unpacking request data (**request.data, **request.POST) or uses fields='__all__' in serializers, enabling mass assignment attacks."
---

## Overview

This rule detects Django code that creates model instances by directly unpacking request data (e.g., `Model.objects.create(**request.data)`) or Django REST Framework serializers that expose all model fields via `fields = '__all__'`. Mass assignment occurs when an attacker includes unexpected fields in a request — such as `is_staff`, `is_superuser`, or `price` — and the application blindly persists them.

**Severity:** High | **CWE:** [CWE-915 – Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

## Why This Matters

Mass assignment is one of the most exploited web application vulnerabilities because:

- It requires zero special tools — an attacker simply adds extra fields to a normal HTTP request
- It can escalate privileges instantly (`is_admin: true`, `role: "superuser"`)
- It can manipulate business logic (`price: 0`, `discount: 100`, `verified: true`)
- It bypasses form-level validation because the attacker sends raw JSON/POST data
- Django and DRF will silently accept and persist extra fields unless explicitly restricted

The OWASP API Security Top 10 lists mass assignment as [API6:2023 – Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/).

## What Gets Flagged

**Pattern 1: Direct request data unpacking into model creation**

```python
# Flagged: all request data flows into model fields
User.objects.create(**request.data)
Profile.objects.create(**request.POST)
```

**Pattern 2: DRF serializer with fields='\_\_all\_\_'**

```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # Flagged: exposes every field including is_staff, is_superuser, password
        fields = '__all__'
```

The rule applies only to `.py` files.

## Remediation

1. **Explicitly list the fields you intend to set.** Never unpack all request data into a model:

   ```python
   # Safe: only the expected fields are used
   User.objects.create(
       username=request.data["username"],
       email=request.data["email"],
   )
   ```

2. **Use Django Forms or DRF Serializers with explicit field lists.** These act as an allowlist for incoming data:

   ```python
   class UserSerializer(serializers.ModelSerializer):
       class Meta:
           model = User
           # Safe: only these three fields are accepted from input
           fields = ["username", "email", "bio"]
           # Extra safety: mark sensitive fields as read-only
           read_only_fields = ["is_staff", "is_superuser", "date_joined"]
   ```

3. **Use `read_only_fields` for sensitive attributes.** Even with an explicit field list, mark fields that should never be set by users:

   ```python
   class ProductSerializer(serializers.ModelSerializer):
       class Meta:
           model = Product
           fields = ["name", "description", "price", "category"]
           read_only_fields = ["price"]  # Only admins can change price
   ```

4. **Validate and clean incoming data before model operations.** Use Django's form validation:

   ```python
   form = UserCreationForm(request.POST)
   if form.is_valid():
       user = form.save()  # Only form-declared fields are saved
   ```

5. **Use `exclude` cautiously — prefer explicit `fields`.** While `exclude` works, it's fragile: adding a new model field automatically exposes it unless you remember to update the exclusion list.

## References

- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [OWASP API Security Top 10 – API6:2023 Mass Assignment](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CAPEC-78: Using Slashes in Alternate Encoding](https://capec.mitre.org/data/definitions/78.html)
- [MITRE ATT&CK T1565 – Data Manipulation](https://attack.mitre.org/techniques/T1565/)
- [Django REST Framework Serializers Documentation](https://www.django-rest-framework.org/api-guide/serializers/)
- [Django ModelForm Documentation](https://docs.djangoproject.com/en/stable/topics/forms/modelforms/)
