package com.acme;

import java.util.*;
import java.util.concurrent.Future;

public class Others {
    Object m(Map<String, Object> map) { return map.get("k"); }
    Object f(Future<Object> fut) throws Exception { return fut.get(); }
    Object l(List<Object> xs) { return xs.get(0); }
    // repo.findById(1L).get() in comment
    String s = "repo.findById(id).get()";
}
