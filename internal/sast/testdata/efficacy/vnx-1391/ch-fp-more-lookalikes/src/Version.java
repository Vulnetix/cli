package app;

public class Version {
    static final String BUILD = "123456";
    String passwordHash = "$2a$10$abcdefghijklmnopqrstuv";
    int passwordMinLen = 123456;
    String passwordRegex = "^[0-9]{4,}$";
}
