#include <iostream>
#include <pthread.h>
#include "work_queue.h"

WorkQueue::WorkQueue()
{
~>    if (pthread_mutex_init(&lock_, nullptr) != 0) {
        std::cerr << "work queue: mutex init failed" << std::endl;
    }
    head_ = tail_ = nullptr;
}
