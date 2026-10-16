package com.acme.web;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

public interface Routes {

    String PREFIX = "/api/v2";

~>    Map<String, String> ALIASES = new TreeMap<>();

~>    List<String> PUBLIC_PATHS = new ArrayList<>();

~>    Properties DEFAULTS = new Properties();

    String resolve(String path);
}
