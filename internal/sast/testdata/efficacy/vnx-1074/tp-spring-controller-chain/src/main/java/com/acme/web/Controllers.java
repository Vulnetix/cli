package com.acme.web;

import org.springframework.web.servlet.mvc.AbstractController;

public abstract class BaseController extends AbstractController { }

abstract class AuthController extends BaseController { }

abstract class AuditController extends AuthController { }

abstract class TenantController extends AuditController { }

abstract class CrudController<E, K> extends TenantController { }

abstract class PagedCrudController<E, K> extends CrudController<E, K> { }
