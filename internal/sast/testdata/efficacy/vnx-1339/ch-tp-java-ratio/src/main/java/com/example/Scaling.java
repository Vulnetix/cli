package com.example;

public class Scaling {
    public boolean isDefault(double ratio, float alpha) {
~>        if (ratio == 0.7) {
            return true;
        }
~>        return alpha != 0.2f;
    }
}
