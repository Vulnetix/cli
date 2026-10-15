package com.acme.expr;

import java.util.Map;

abstract class Node<T> extends java.util.AbstractList<T> {
}

abstract class Expr<T> extends Node<T> {
}

abstract class BinaryExpr<T> extends Expr<Map<String, T>> {
}

abstract class ArithExpr extends BinaryExpr<Integer> {
}

abstract class AddLike extends ArithExpr {
}

class Add extends AddLike {
}

~>strictfp class CheckedAdd extends Add {
}

~>final class SaturatingAdd extends CheckedAdd {
}
