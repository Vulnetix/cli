package org.example.legacy;

import org.junit.jupiter.api.Test;

class FinalizerProbeTest {
    static class Probe {
        boolean ran;

        @Override
        public void finalize() {
            ran = true;
        }
    }

    @Test
    void runsFinalizer() {
        Probe p = new Probe();
        p.finalize();
    }
}
