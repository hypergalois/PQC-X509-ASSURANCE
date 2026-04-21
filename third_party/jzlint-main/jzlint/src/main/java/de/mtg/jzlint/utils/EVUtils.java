package de.mtg.jzlint.utils;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;

public final class EVUtils {

    private EVUtils() {
        //
    }

    private static final List<String> evOids = Arrays.asList(
            "2.23.140.1.1",
            "1.3.159.1.17.1",
            "1.3.6.1.4.1.34697.2.1",
            "1.3.6.1.4.1.34697.2.2",
            "1.3.6.1.4.1.34697.2.3",
            "1.3.6.1.4.1.34697.2.4",
            "1.2.40.0.17.1.22",
            "2.16.578.1.26.1.3.3",
            "1.3.6.1.4.1.17326.10.14.2.1.2",
            "1.3.6.1.4.1.17326.10.8.2.1.2",
            "1.3.6.1.4.1.6449.1.2.1.5.1",
            "2.16.840.1.114412.2.1",
            "2.16.840.1.114412.1.3.0.2",
            "2.16.528.1.1001.1.1.1.12.6.1.1.1",
            "2.16.792.3.0.4.1.1.4",
            "2.16.840.1.114028.10.1.2",
            "0.4.0.2042.1.4",
            "0.4.0.2042.1.5",
            "1.3.6.1.4.1.13177.10.1.3.10",
            "1.3.6.1.4.1.14370.1.6",
            "1.3.6.1.4.1.4146.1.1",
            "2.16.840.1.114413.1.7.23.3",
            "1.3.6.1.4.1.14777.6.1.1",
            "2.16.792.1.2.1.1.5.7.1.9",
            "1.3.6.1.4.1.782.1.2.1.8.1",
            "1.3.6.1.4.1.22234.2.5.2.3.1",
            "1.3.6.1.4.1.8024.0.2.100.1.2",
            "1.2.392.200091.100.721.1",
            "2.16.840.1.114414.1.7.23.3",
            "1.3.6.1.4.1.23223.2",
            "1.3.6.1.4.1.23223.1.1.1",
            "2.16.756.1.83.21.0",
            "2.16.756.1.89.1.2.1.1",
            "1.3.6.1.4.1.7879.13.24.1",
            "2.16.840.1.113733.1.7.48.1",
            "2.16.840.1.114404.1.1.2.4.1",
            "2.16.840.1.113733.1.7.23.6",
            "1.3.6.1.4.1.6334.1.100.1",
            "2.16.840.1.114171.500.9",
            "1.3.6.1.4.1.36305.2"
    );


    public static boolean isEV(X509Certificate certificate) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(ASN1OctetString.getInstance(rawCertificatePolicies).getOctets());

        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(p -> evOids.contains(p.getPolicyIdentifier().getId()));
    }


}
