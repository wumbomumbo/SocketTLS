package org.bouncycastle.math.ec.endo;

import bcjavastub.math.BigInteger;

public interface GLVEndomorphism extends ECEndomorphism
{
    BigInteger[] decomposeScalar(BigInteger k);
}
