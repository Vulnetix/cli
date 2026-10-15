---
title: "VNX-1045 – Parent Class with Virtual Destructor and Child Without Virtual Destructor"
description: "Reports a C++ child class whose own destructor is declared without virtual, override or final although a parent in its base list declares a virtual destructor."
---

## Overview

VNX-1045 reports [CWE-1045](https://cwe.mitre.org/data/definitions/1045.html) in C++. The case is a class that derives from a parent whose destructor is declared `virtual`, and that declares its own destructor without `virtual`, `override` or `final`.

The finding is on the child's in-class destructor declaration: `~Child();`, `~Child() = default;`, `~Child() noexcept;` or an inline body. The parent can be named with any access specifier, with or without a namespace or template arguments, in a base list on the class line or wrapped onto the following lines (`class Child\n    : public Base {`), and can be declared in any C++ file of the scanned tree with a destructor marked `virtual` (including on the line above), `override` or `final`, so a grandchild of a virtual base is judged too.

Not reported:

- A child destructor marked `virtual`, `override` or `final`.
- A child with no user-declared destructor. The implicit destructor is virtual and needs no annotation.
- A parent whose destructor is not virtual. That is a different and more dangerous weakness (CWE-1079 and CWE-1087), judged by VNX-1079 and VNX-1087.
- A parent defined outside the scanned tree.
- Out-of-class definitions (`Child::~Child() {}`), test code and comments.

**Severity:** Medium | **CWE:** [CWE-1045](https://cwe.mitre.org/data/definitions/1045.html)

## Why This Matters

C++ makes the child's destructor virtual anyway, so today the code is correct. The problem is that the declaration reads as non-virtual. A reviewer cannot tell from the child alone whether `delete base_ptr` runs it. If the parent's `virtual` is ever removed, for example in a refactor that turns the parent into a plain value type, every child silently loses its virtual destructor. Deleting through a parent pointer then skips the child's cleanup, which leaks memory and handles or leaves half-destroyed state behind. `override` turns that silent change into a compile error.

## What Gets Flagged

```cpp
class Codec {
public:
    virtual ~Codec() = default;
};

class GzipCodec : public Codec {
public:
    ~GzipCodec();                  // FLAGGED
};

class Socket : private NonCopyable, public Stream<char> {
public:
    ~Socket() = default;           // FLAGGED: Stream<T> declares virtual ~Stream()
};
```

## What Is Not Flagged

```cpp
class GzipCodec : public Codec {
public:
    ~GzipCodec() override;
};

class LzCodec : public Codec {     // no user-declared destructor
    int encode() override;
};
```

## Remediation

1. Declare the child's destructor `override` (`~GzipCodec() override;`), or `virtual` if your style guide prefers it.
2. Turn on `-Winconsistent-missing-destructor-override` (Clang) or clang-tidy's `modernize-use-override` to enforce it.
3. If the child needs no cleanup, remove the user-declared destructor and rely on the implicit one.

## References

- [CWE-1045: Parent Class with a Virtual Destructor and a Child Class without a Virtual Destructor](https://cwe.mitre.org/data/definitions/1045.html)
- [C++ Core Guidelines C.128: Virtual functions should specify exactly one of virtual, override, or final](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#c128-virtual-functions-should-specify-exactly-one-of-virtual-override-or-final)
