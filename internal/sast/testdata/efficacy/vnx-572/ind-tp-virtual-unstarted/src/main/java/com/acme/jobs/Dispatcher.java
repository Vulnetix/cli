package com.acme.jobs;

public class Dispatcher {
    public void dispatch(Runnable job) {
        Thread vt = Thread.ofVirtual()
                .name("job-", 0)
                .unstarted(job);
~>        vt.run();
    }
}
