package com.acme.model;

import java.io.Serializable;

~>public abstract class Entity implements Serializable {
	protected Long id;

	public Long getId() {
		return id;
	}
}
