package de.mtg.jzlint.utils;

import java.security.cert.X509Certificate;

public final class BRUtils {

    private BRUtils() {
        // empty
    }

    public static boolean isDomainValidated(X509Certificate certificate) {
        return Utils.containsPolicyOID(certificate, "2.23.140.1.2.1");
    }

    public static boolean isIndividualValidated(X509Certificate certificate) {
        return Utils.containsPolicyOID(certificate, "2.23.140.1.2.3");
    }

    public static boolean isOrganizationValidated(X509Certificate certificate) {
        return Utils.containsPolicyOID(certificate, "2.23.140.1.2.2");
    }

    public static boolean isExtendedValidated(X509Certificate certificate) {
        return Utils.containsPolicyOID(certificate, "2.23.140.1.1");
    }

    public static boolean hasPubliclyTrustedTLSServerPolicyOID(X509Certificate certificate) {
        return isDomainValidated(certificate) || isIndividualValidated(certificate) || isOrganizationValidated(certificate);
    }

}
