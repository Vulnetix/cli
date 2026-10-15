package com.acme.repo;

abstract class Cached<T> extends Base<T> { }

abstract class Audited<T extends Comparable<T>> extends Cached<T> { }

abstract class Secured<T extends Comparable<T>> extends com.acme.repo.Audited<T> { }

abstract class Paged<T extends Comparable<T>>
    extends Secured<T> { }

abstract class Sorted<T extends Comparable<T>> extends Secured<T> { }

abstract class Filtered<T extends Comparable<T>> extends Sorted<T> { }

abstract class Indexed<T extends Comparable<T>> extends Filtered<T> { }

