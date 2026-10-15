class Wait {
    void await(int seen, int expected) throws TimeoutException {
        while (seen < expected) {
            if (expired()) {
                throw new TimeoutException();
            }
            poll();
        }
    }
}
