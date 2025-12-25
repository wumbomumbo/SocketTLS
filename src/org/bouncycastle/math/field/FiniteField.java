package org.bouncycastle.math.field;

import bcjavastub.math.BigInteger;

public interface FiniteField
{
    BigInteger getCharacteristic();

    int getDimension();
}
