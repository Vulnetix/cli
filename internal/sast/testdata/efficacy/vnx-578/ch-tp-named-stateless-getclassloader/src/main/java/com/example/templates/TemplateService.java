package com.example.templates;

import java.io.InputStream;
import javax.ejb.Local;
import javax.ejb.Stateless;

@Stateless(name = "TemplateService", mappedName = "ejb/templates")
@Local(TemplateApi.class)
public class TemplateService implements TemplateApi {

    @Override
    public InputStream open(String name) {
~>        ClassLoader cl = TemplateService.class.getClassLoader();
        return cl.getResourceAsStream("templates/" + name);
    }
}
