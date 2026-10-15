package org.example;

import java.util.List;

final class Scheduler {
    int plan(List<int[]> jobs) {
        int slot = 0;
        for (int k = 0; k < jobs.size(); k++) {
            if (jobs.get(k) == null) {
                slot--;
            }
~>            for (k = 0; k < jobs.get(0).length; k++) {
                slot += jobs.get(0)[k];
            }
        }
        return slot;
    }
}
