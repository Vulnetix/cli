package com.acme.web;

import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Named;

/**
 * Not an @Entity; a request-scoped form backing bean.
 * An @SessionScoped bean must be Serializable, this one need not be.
 */
@Named
@RequestScoped
public class SearchForm {
    private String query;
}
