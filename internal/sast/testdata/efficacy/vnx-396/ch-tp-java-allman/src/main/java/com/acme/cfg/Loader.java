package com.acme.cfg;

import java.util.Optional;

public class Loader
{
    public Optional<Config> load(String name)
    {
        try
        {
            return Optional.of(parser.parse(name));
        }
~>        catch (Exception e)
        {
            log.warn("could not load config");
            return Optional.empty();
        }
    }

    public Optional<Config> loadLogged(String name)
    {
        try
        {
            return Optional.of(parser.parse(name));
        }
        catch (Exception e)
        {
            log.warn("could not load config", e);
            return Optional.empty();
        }
    }
}
