package org.bouncycastle.util;

import bcjavastub.util.Collection;

public interface Store
{
    Collection getMatches(Selector selector)
        throws StoreException;
}
