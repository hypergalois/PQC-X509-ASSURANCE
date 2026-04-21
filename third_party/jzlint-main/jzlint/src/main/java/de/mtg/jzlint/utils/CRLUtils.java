package de.mtg.jzlint.utils;

import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

public final class CRLUtils {

    private CRLUtils() {
        // empty
    }

    public static boolean hasExtension(X509CRL crl, String oid) {
        return crl.getExtensionValue(oid) != null;
    }

    public static boolean containsRevokedCertificates(X509CRL crl) {
        Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();
        return revokedCertificates != null && revokedCertificates.size() > 0;
    }

    public static boolean hasExtensions(X509CRL crl) {

        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(crl.getEncoded());
            ASN1Sequence tbsCertList = (ASN1Sequence) seq.getObjectAt(0);

            // get the latest element and check if it is tagged.
            if (tbsCertList.getObjectAt(tbsCertList.size() - 1) instanceof ASN1TaggedObject) {
                return ((ASN1TaggedObject) tbsCertList.getObjectAt(tbsCertList.size() - 1)).getTagNo() == 0;
            }
            return false;
        } catch (CRLException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static boolean atLeastOneCrlEntryHasExtension(X509CRL crl, String oid) {

        Set<? extends X509CRLEntry> revokedCertificates = crl.getRevokedCertificates();

        if (revokedCertificates == null || revokedCertificates.isEmpty()) {
            return false;
        }

        for (X509CRLEntry crlEntry : revokedCertificates) {
            if (Optional.ofNullable(crlEntry.getExtensionValue(oid)).isPresent()) {
                return true;
            }
        }
        return false;
    }

}
