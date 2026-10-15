package com.acme;

public class Gate {
    public boolean allow(User u) {
        if (u.isAdmin()) { return true; }
        if (u.isBlocked()) {
            return false;
        } else {
            audit(u);
        }
        for (String r : u.roles()) {
            check(r);
        }
        while (u.pending()) u.next();
        synchronized (this) { count++; }
        try {
            persist();
        } finally {
            release();
        }
        return true;
    }
}

class Early {
    void f(Response response) throws java.io.IOException {
        if (!response.isSuccessful()) throw new java.io.IOException("Unexpected code " + response);
        if (response.isEmpty()) return;
        if (response.code() > 300) log(response.code());
    }
}
