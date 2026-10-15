package com.acme.api;

interface I1 extends java.io.Serializable {}
interface I2 extends I1 {}
interface I3 extends I2 {}
interface I4 extends I3 {}
interface I5 extends I4 {}
interface I6 extends I5 {}
interface I7 extends I6 {}
public class Chain implements I7 {
}
