package com.acme.billing;

import java.io.FileOutputStream;
import java.util.concurrent.Executors;
import org.springframework.stereotype.Service;

@Service
public class ReportService {
    public void run() throws Exception {
        Executors.newSingleThreadExecutor().submit(this::work);
        new Thread(this::work).start();
        try (FileOutputStream out = new FileOutputStream("r.txt")) {
            out.write(1);
        }
    }

    private synchronized void work() {}
}
