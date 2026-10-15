package com.acme.model;

import java.io.Serializable;
import java.util.List;

@Getter
@AllArgsConstructor
~>public final class Page<T extends Comparable<T>>
        extends AbstractPage
        implements Iterable<T>, java.io.Serializable, Cloneable {
    private final List<T> items;
    private final int number;
}
