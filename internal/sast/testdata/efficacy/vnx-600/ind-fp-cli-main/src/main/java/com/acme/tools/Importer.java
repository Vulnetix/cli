package com.acme.tools;

import java.util.UUID;

public final class Importer {

    public static void main(String[] argv) {
        int batch = Integer.parseInt(argv[0]);
        UUID tenant = UUID.fromString(argv[1]);
        // int id = Integer.parseInt(request.getParameter("id"));
        new Importer().run(tenant, batch);
    }

    private void run(UUID tenant, int batch) {
    }
}
