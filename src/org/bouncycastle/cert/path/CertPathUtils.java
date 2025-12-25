package org.bouncycastle.cert.path;


import org.bouncycastle.cert.X509CertificateHolder;

import bcjavastub.util.HashSet;
import bcjavastub.util.Set;

class CertPathUtils
{
    static Set getCriticalExtensionsOIDs(X509CertificateHolder[] certificates)
    {
        Set criticalExtensions = new HashSet();

        for (int i = 0; i != certificates.length; i++)
        {
            criticalExtensions.addAll(certificates[i].getCriticalExtensionOIDs());
        }

        return criticalExtensions;
    }
}
