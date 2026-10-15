package com.acme.jobs;

public class Backfill {

    void run(Repository repo, long maxId) {
~>        for (Long id = 1L; id <= maxId; id++) {
            repo.touch(id);
        }
    }

    int drain(Queue queue) {
        Integer processed = 0;
        do {
            queue.poll();
~>            processed = processed + 1;
        } while (!queue.isEmpty());
        return processed;
    }
}
