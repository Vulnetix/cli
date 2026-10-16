class Main {
  void f(String password, String name) {
    log.info("Loading config for " + name);
    String msg = "enter password";
    authenticate(name, password);
  }
}
