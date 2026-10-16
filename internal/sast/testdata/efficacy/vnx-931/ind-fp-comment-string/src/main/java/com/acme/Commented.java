package com.acme;

class Commented {
    // .anyRequest().permitAll() was removed, see ticket
    String doc = ".antMatchers(\"/admin/**\").permitAll()";
    /* .requestMatchers("/**").permitAll() */
}
