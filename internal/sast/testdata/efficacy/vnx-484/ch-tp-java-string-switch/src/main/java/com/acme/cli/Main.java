package com.acme.cli;

public class Main {
    static int run(String verb, Config cfg) {
        int code = 0;
        switch (verb) {
            case "init":
                cfg.reset();
                break;
~>            case "deploy":
                cfg.setTarget(System.getenv("TARGET"));
                code = Deployer.deploy(cfg,
                        true);
            case "destroy":
                code = Deployer.destroy(cfg);
                break;
            default:
                throw new IllegalArgumentException(verb);
        }
        return code;
    }
}
