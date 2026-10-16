package com.acme.jobs;

import java.util.List;

public class FakeQueue {
    private List<Job> recorded;

    public void setRecorded(List<Job> recorded) {
        this.recorded = recorded;
    }
}
