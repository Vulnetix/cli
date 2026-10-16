package com.acme;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public final class MigrateCommand {

    public static void main(String[] args) throws Exception {
        ExecutorService worker = Executors.newFixedThreadPool(1);
        for (String file : args) {
            worker.submit(() -> Migrator.apply(Files.readString(Path.of(file))));
        }
        worker.shutdown();
        worker.awaitTermination(1, TimeUnit.HOURS);
    }
}
