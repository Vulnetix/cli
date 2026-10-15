package com.acme.repo;

~>public class UserRepo extends Indexed<String> {
    String load(long id) { return null; }
}

~>class AdminRepo extends UserRepo { }
