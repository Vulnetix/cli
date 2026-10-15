package com.acme.exec;

public class Runner {
    int run(Executor ex) {
        try {
            return ex.execute();
        } finally {
            ex.submit(new Runnable() {
                @Override
                public void run() {
                    return;
                }
            });
            ex.shutdown();
        }
    }

    int after() {
        try {
            work();
        } finally {
            cleanup();
        }
        return 0;
    }
}
