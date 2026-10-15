package com.acme.io;

import java.io.Closeable;
import java.io.IOException;

public final class Closer
{
    public static void closeQuietly(Closeable c)
    {
        try
        {
            c.close();
        }
        catch (IOException e)
        {
            // closing is best effort: the data was already flushed
        }
    }

    public static void closeAll(Closeable a) {
        try {
            a.close();
        } catch (IOException e) { /* nothing useful to do on close */ }
    }
}
