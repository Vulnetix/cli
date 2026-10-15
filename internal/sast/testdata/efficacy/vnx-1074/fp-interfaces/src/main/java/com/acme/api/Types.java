package com.acme.api;

interface A { }
interface B extends A { }
interface C extends B { }
interface D extends C { }
interface E extends D { }
interface F extends E { }
interface G extends F { }
interface H extends G { }

public class Impl implements H {
}

class Holder<T extends H> extends Impl {
    // class Deep extends Holder: a comment, not a declaration
    String s = "class Fake extends Holder";
}
