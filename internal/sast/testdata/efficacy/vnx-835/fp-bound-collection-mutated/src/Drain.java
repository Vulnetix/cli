class Drain {
    void drain(java.util.Deque<Job> q, int keep) {
        while (keep < q.size()) {
            q.poll();
        }
    }
}
