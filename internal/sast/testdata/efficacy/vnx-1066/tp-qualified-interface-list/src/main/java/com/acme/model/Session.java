package com.acme.model;

~>abstract class Session<T> extends BaseEntity implements Cloneable, java.io.Serializable {
    protected T owner;
}
