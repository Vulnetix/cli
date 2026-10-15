package com.acme.plugin;

public abstract class Plugin {
~>    public abstract void start(Context ctx) throws Exception;

~>    static Plugin load(String name) throws Throwable {
        return (Plugin) Class.forName(name).getDeclaredConstructor().newInstance();
    }
}
