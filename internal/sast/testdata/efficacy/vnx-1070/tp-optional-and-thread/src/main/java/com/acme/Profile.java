package com.acme;

import java.util.Optional;

public final class Profile implements java.io.Serializable {
~>    private Optional<String> nickname = Optional.empty();
~>    private volatile Thread refresher;
~>    private java.io.PrintWriter audit;
}
