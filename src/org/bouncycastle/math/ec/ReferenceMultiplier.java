package org.bouncycastle.math.ec;

import bcjavastub.math.BigInteger;

public class ReferenceMultiplier extends AbstractECMultiplier
{
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        return ECAlgorithms.referenceMultiply(p, k);
    }
}
