package org.example.build;

public class Pipeline {
    private final Builder builder = new Builder();

    public Artifact build(Context ctx) {
        builder.finalize(ctx);
        builder.finalizeBuild();
        Artifact a = builder.finalizeArtifact(ctx, true);
        System.runFinalization();
        // do not call resource.finalize() directly
        String hint = "call close() instead of x.finalize()";
        return a;
    }
}
