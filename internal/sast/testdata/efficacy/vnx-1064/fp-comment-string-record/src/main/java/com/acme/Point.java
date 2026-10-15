package com.acme;

// void old(int a, int b, int c, int d, int e, int f, int g, int h) {}
public record Point(int x, int y, int z, int w, int u, int v, int s, int t) {
    static final String SIG = "void f(int a, int b, int c, int d, int e, int f, int g, int h) {";
}
