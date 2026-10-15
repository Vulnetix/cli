package com.acme.tx;

public class Committer {
    boolean commit(Tx tx) {
        try {
            tx.flush();
            return true;
        }
        finally
        {
            if (tx.isRolledBack()) {
~>                return false;
            }
            tx.close();
        }
    }
}
