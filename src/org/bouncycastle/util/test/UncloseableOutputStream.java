package org.bouncycastle.util.test;

import java.io.IOException;
import java.io.OutputStream;

import bcjavastub.io.FilterOutputStream;

public class UncloseableOutputStream extends FilterOutputStream
{
    public UncloseableOutputStream(OutputStream s)
    {
        super(s);
    }

    public void close()
    {
        throw new RuntimeException("close() called on UncloseableOutputStream");
    }

    public void write(byte[] b, int off, int len) throws IOException
    {
        out.write(b, off, len);
    }
 }
