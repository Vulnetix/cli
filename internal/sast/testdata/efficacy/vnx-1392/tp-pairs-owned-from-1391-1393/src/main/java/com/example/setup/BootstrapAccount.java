package com.example.setup;

public final class BootstrapAccount {

  private static final String BOOT_USERNAME = "admin";
~>  private static final String BOOT_PASSWORD = "admin";

  private BootstrapAccount() {}

  public static String[] credentials() {
    return new String[] {BOOT_USERNAME, BOOT_PASSWORD};
  }
}
