package com.acme.build;

public class Pipeline {
    void run(Builder builder, Context ctx) {
        builder.finalizeBuild();
        builder.finalize(ctx);
        Builder.finalizeAll();
        System.runFinalization();
        String hint = "never call obj.finalize() yourself";
        // conn.finalize();
    }
}
