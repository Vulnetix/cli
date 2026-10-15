package com.acme.api;

/**
 * Example: String[] NAMES = {"a"}; would be a mutable constant.
 */
public interface Codec {
  String NAME = "codec";
  String[] NO_ALIASES = {};
  int[] NO_SIZES = new int[0];

  byte[] encode(String value);

  default byte[] encodeAll(String[] values) {
    byte[] out = new byte[values.length];
    String[] copy = values.clone();
    return out;
  }
}
