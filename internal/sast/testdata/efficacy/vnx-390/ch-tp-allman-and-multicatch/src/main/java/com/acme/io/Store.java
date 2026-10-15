package com.acme.io;

import java.io.IOException;
import java.sql.SQLException;

public class Store
{
    public void flush()
    {
        try
        {
            writeAll();
        }
~>        catch (IOException | SQLException ex)
        {
        }
    }

    public void close() {
        try {
            release();
~>        } catch (IOException | IllegalStateException err) { }
    }

    private void writeAll() throws IOException, SQLException {}
    private void release() throws IOException {}
}
