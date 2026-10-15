---
title: "VNX-RUBY-006 – Ruby Mass Assignment"
description: "Reports request parameters reaching ActiveRecord create/update/new/assign_attributes/find_or_create_by and similar calls without a strong-parameters allowlist, every params.permit! call, and permit lists (single- or multi-line) that admit admin, role or permissions attributes outside admin controllers."
---

## Overview

This rule flags ActiveRecord method calls — `create()`, `new()`, `update()`, `update_attributes()`, and `assign_attributes()` — where the raw `params` hash (or a slice of it) is passed directly without filtering through Rails strong parameters. Mass assignment allows an attacker to set any attribute on a model that ActiveRecord will accept, including fields that should only be set by the application itself: `admin`, `role`, `confirmed`, `balance`, `permissions`, and any other attribute present in the database schema. This maps to [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html).

**Severity:** High | **CWE:** [CWE-915 – Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)

## Why This Matters

Mass assignment was one of the most impactful vulnerabilities in early Rails applications. The most famous real-world case involved GitHub in 2012: a researcher demonstrated that passing `public_keys[user][organization_attributes][repos_attributes][0][public_key_attributes][user_attributes][bypass]=true` to a mass-assignment endpoint allowed forking a private repository that belonged to a different user — a full authorization bypass achieved entirely through parameter manipulation, with no exploit code required.

Modern Rails 4+ applications are protected by strong parameters (`ActionController::StrongParameters`) if they use it correctly, but `params.permit!` (which allows everything), passing raw `params` directly, or calling `params[key]` and passing the result to a model method all bypass the protection. The rule catches the common patterns where the raw params object reaches an ActiveRecord write method.

The consequences range from horizontal privilege escalation (setting `confirmed = true` to skip email verification), to vertical privilege escalation (setting `admin = true` or `role = 'admin'`), to financial fraud (modifying `balance` or `discount_rate`), depending on what attributes your models expose.

## What Gets Flagged

The rule reports, in `.rb` files:

- an attribute-assigning call (`create`, `update`, `update_attributes`, `assign_attributes`, `attributes=`, `find_or_create_by`, `first_or_create`, `insert_all`, `upsert`, `build`, `Model.new`) given `params[...]`, `request.params`, `params.to_unsafe_h` or a `.permit!` result, directly or through a variable assigned from one in the 15 lines above;
- every `.permit!` call;
- a `.permit(...)` list containing `:admin`, `:role`, `:role_id`, `:roles`, `:superuser` or `:permissions` outside an admin controller.

```ruby
@post = Post.create(params[:post])                   # FLAGGED

attrs = params[:account]
attrs = attrs.merge(owner_id: current_user.id)
@account = Account.new(attrs)                        # FLAGGED: two-step flow

params.require(:setting).permit!                     # FLAGGED
params.require(:user).permit(:name, :email, :admin)  # FLAGGED: privilege attribute
```

Not flagged: `params.require(:x).permit(...)` or `.slice(...)` results, a single scalar (`update(name: params[:name])`), `SearchForm.new(params)` with the bare hash (form objects), `options.update(params)` on hashes, `OpenStruct`/`Struct.new`, and privilege attributes permitted under `app/controllers/admin/`.

## Remediation

1. **Use Rails strong parameters with `require` and `permit`.** `params.require(:model_name)` asserts that the expected top-level key is present and raises `ActionController::ParameterMissing` if it is not. `.permit(:field1, :field2)` creates an allowlist of the fields the user is allowed to set — all other fields are silently removed from the hash:

```ruby
# SAFE: strong parameters — only permitted fields pass through
def user_params
  params.require(:user).permit(:name, :email, :password, :password_confirmation)
  # Note: :admin, :role, :confirmed are NOT listed — users cannot set them
end

def create
  @user = User.new(user_params)
  if @user.save
    redirect_to @user
  else
    render :new, status: :unprocessable_entity
  end
end

def update
  if @user.update(user_params)
    redirect_to @user
  else
    render :edit, status: :unprocessable_entity
  end
end
```

2. **Permit nested attributes explicitly.** For associations loaded via `accepts_nested_attributes_for`, you must explicitly permit nested keys — strong parameters does not automatically permit nested hashes:

```ruby
# SAFE: nested attributes permitted explicitly
def post_params
  params.require(:post).permit(
    :title,
    :body,
    :published,
    tags_attributes: [:id, :name, :_destroy],
    author_attributes: [:id, :bio]
  )
end
```

3. **Use separate parameter methods for different roles.** Administrative actions that legitimately need to set protected fields should have their own parameter method, called only from admin-authenticated controller actions:

```ruby
# SAFE: admin-only parameter method — called only after authorizing admin access
def admin_user_params
  params.require(:user).permit(:name, :email, :role, :admin, :confirmed)
end

def user_params
  params.require(:user).permit(:name, :email, :password, :password_confirmation)
end
```

4. **Never use `params.permit!`** in production code. `permit!` marks all parameters as permitted and is functionally equivalent to the old `attr_accessible` mass assignment without restrictions. It is only appropriate in tests or scripts running with full trust.

5. **Set sensitive attributes explicitly after creation** rather than permitting them through the parameter allowlist:

```ruby
# SAFE: set sensitive fields explicitly — not through user-supplied params
def create
  @user = User.new(user_params)
  @user.confirmed_at = nil      # force email confirmation
  @user.role = 'user'           # ensure role is always set to default
  @user.organization = current_user.organization  # set from auth context

  if @user.save
    redirect_to @user
  else
    render :new, status: :unprocessable_entity
  end
end
```

6. **Audit `params.permit!` and any place `params` is passed to a model directly** across the entire codebase. In inherited resources, concerns, or base controllers, a permissive parameter pattern can affect many controllers at once.

## References

- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [CAPEC-17: Using Malicious Files](https://capec.mitre.org/data/definitions/17.html)
- [Rails Security Guide – Mass Assignment](https://guides.rubyonrails.org/security.html#mass-assignment)
- [Rails Guide – Strong Parameters](https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [Rails API – ActionController::StrongParameters](https://api.rubyonrails.org/classes/ActionController/StrongParameters.html)
- [GitHub mass assignment vulnerability (2012)](https://github.blog/2012-03-04-public-key-security-vulnerability-and-corrective-action/)
