package com.acme.ui;

public class KeyboardLayout {
    public boolean sameMonkeys(int[] monkeyIds, int[] others) {
        for (int i = 0; i < monkeyIds.length; i++) {
            if (monkeyIds[i] != others[i]) return false;
        }
        return true;
    }

    public boolean sameAuthors(String authorList, String other) {
        for (int i = 0; i < authorList.length(); i++) {
            if (authorList.charAt(i) != other.charAt(i)) {
                return false;
            }
        }
        return true;
    }

    public boolean sameSignals(double[] signalSamples, double[] reference) {
        for (int i = 0; i < signalSamples.length; i++) {
            if (signalSamples[i] != reference[i]) return false;
        }
        return true;
    }
}
