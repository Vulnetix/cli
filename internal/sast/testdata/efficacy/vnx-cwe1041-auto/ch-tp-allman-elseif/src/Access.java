package com.acme;

public class Access {
    int level(User u) {
        if (u.isAdmin())
        {
            return 3;
        }
        else if (u.isStaff())
        {
            return 2;
        }
~>        else if (u.isAdmin())
        {
            return 1;
        }
        return 0;
    }
}
