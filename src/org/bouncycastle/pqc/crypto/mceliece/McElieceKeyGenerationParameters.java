package org.bouncycastle.pqc.crypto.mceliece;


import org.bouncycastle.crypto.KeyGenerationParameters;

import bcjavastub.security.SecureRandom;

public class McElieceKeyGenerationParameters
    extends KeyGenerationParameters
{
    private McElieceParameters params;

    public McElieceKeyGenerationParameters(
        SecureRandom random,
        McElieceParameters params)
    {
        // XXX key size?
        super(random, 256);
        this.params = params;
    }

    public McElieceParameters getParameters()
    {
        return params;
    }
}
