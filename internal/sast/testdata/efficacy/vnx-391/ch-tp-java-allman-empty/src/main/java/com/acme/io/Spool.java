package com.acme.io;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class Spool
{
    public void purge(Path dir)
    {
        try
        {
            Files.deleteIfExists(dir.resolve("spool.lock"));
        }
        catch (IOException e)
        {
        }
    }

    public void touch(Path p)
    {
        try
        {
            Files.createFile(p);
        }
~>        catch (IOException e)
        {
            // TODO
        }
    }
}
