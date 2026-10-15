package com.acme.jobs;

public class Runner {
    void run(String name, long id) {
~>        synchronized (("job-" + name).intern()) {
            execute(name);
        }
~>        synchronized (Long.valueOf(id)) {
            execute(name);
        }
    }
}
