package com.acme.index;

import java.nio.file.Path;

public class Indexer {
    static class IndexWorker extends Thread {
        private final Path root;

        IndexWorker(Path root) {
            super("index-worker");
            this.root = root;
        }

        @Override
        public void run() {
            scan(root);
        }

        private void scan(Path p) { }
    }

    public void reindex(Path root) {
        IndexWorker worker = new IndexWorker(root);
~>        worker.run();
    }
}
