package com.example.dao;

import org.hibernate.SessionFactory;

public abstract class BaseDao {

    public void setSessionFactory(SessionFactory sessionFactory) {
        // the factory is resolved per call from the current context
    }

    public void setTokenizer(Object tokenizer) {}
}
