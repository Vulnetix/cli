class Queue {
public:
    void flush() {
        if (empty())
            goto done;
        drain();
    done:
        unlock();
    }

    void reset() {
        if (!dirty_)
            goto done;
        clear();
    done:
        unlock();
    }
};
