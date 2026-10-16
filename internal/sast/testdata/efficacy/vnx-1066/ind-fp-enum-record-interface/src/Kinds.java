package m;

import java.io.Serializable;

public interface Kinds extends Serializable { }

enum Color implements Serializable { RED, GREEN }

record Point(int x, int y) implements Serializable { }
