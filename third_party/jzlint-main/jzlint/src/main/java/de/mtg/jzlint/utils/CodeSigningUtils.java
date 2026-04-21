package de.mtg.jzlint.utils;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.function.Function;
import java.util.function.Predicate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;

public final class CodeSigningUtils {

    public static final String CODE_SIGNING_CERTIFICATE_OID = "2.23.140.1.4.1";
    public static final String EV_CODE_SIGNING_CERTIFICATE_OID = "2.23.140.1.3";
    public static final String TIMESTAMP_CERTIFICATE_OID = "2.23.140.1.4.2";

    private static final Function<PolicyInformation, String> getOID = p -> p.getPolicyIdentifier().getId();

    private CodeSigningUtils() {
        // empty
    }

    public static boolean isCodeSigningCertificate(X509Certificate certificate) {
        return isPolicy(certificate, CODE_SIGNING_CERTIFICATE_OID);
    }

    public static boolean isEvCodeSigningCertificate(X509Certificate certificate) {
        return isPolicy(certificate, EV_CODE_SIGNING_CERTIFICATE_OID);
    }

    public static boolean isTimestampingCertificate(X509Certificate certificate) {
        return isPolicy(certificate, TIMESTAMP_CERTIFICATE_OID);
    }

    public static boolean isCodeSigningSubscriberCertificate(X509Certificate certificate) {
        return isCodeSigningCertificate(certificate) && Utils.isSubscriberCert(certificate);
    }

    public static boolean isEvCodeSigningSubscriberCertificate(X509Certificate certificate) {
        return isEvCodeSigningCertificate(certificate) && Utils.isSubscriberCert(certificate);
    }

    public static boolean isTimestampingSubscriberCertificate(X509Certificate certificate) {
        return isTimestampingCertificate(certificate) && Utils.isSubscriberCert(certificate);
    }

    private static boolean isPolicy(X509Certificate certificate, String policyOID) {
        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(value);

        Predicate<PolicyInformation> isPolicy = p -> policyOID.equalsIgnoreCase(getOID.apply(p));

        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isPolicy);
    }

}
