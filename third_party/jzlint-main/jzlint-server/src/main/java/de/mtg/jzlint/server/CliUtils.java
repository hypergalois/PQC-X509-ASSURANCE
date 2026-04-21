package de.mtg.jzlint.server;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import de.mtg.jzlint.Source;

public class CliUtils {

    public static final String CHECK_APPLIES = "checkApplies";
    public static final String EXECUTE = "execute";

    private CliUtils() {
        // empty
    }

    public static boolean isCertificateIssuerLint(Class<?> lintClass) {
        try {
            lintClass.getMethod(CHECK_APPLIES, X509Certificate.class, X509Certificate.class);
            return true;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    public static boolean isCRLIssuerLint(Class<?> lintClass) {
        try {
            lintClass.getMethod(CHECK_APPLIES, X509CRL.class, X509Certificate.class);
            return true;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    public static boolean isOCSPResponseIssuerLint(Class<?> lintClass) {
        try {
            lintClass.getMethod(CHECK_APPLIES, byte[].class, X509Certificate.class);
            return true;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    public static boolean isCertificateLint(Class<?> lintClass) {
        try {
            lintClass.getMethod(CHECK_APPLIES, X509Certificate.class);
            return true;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    public static boolean isCRLLint(Class<?> lintClass) {
        try {
            lintClass.getMethod(CHECK_APPLIES, X509CRL.class);
            return true;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    public static boolean isOCSPResponseLint(Class<?> lintClass) {
        try {
            lintClass.getMethod(CHECK_APPLIES, byte[].class);
            return true;
        } catch (NoSuchMethodException e) {
            return false;
        }
    }

    public static boolean includeLint(Source lintSource, List<String> includeSources, List<String> excludeSources) {

        boolean includeIsEmpty = includeSources == null || includeSources.isEmpty();
        boolean excludeIsEmpty = excludeSources == null || excludeSources.isEmpty();

        if (!includeIsEmpty) {
            return includeSources.contains(lintSource.getSourceName());
        }

        if (!excludeIsEmpty) {
            return !excludeSources.contains(lintSource.getSourceName());
        }

        return true;
    }

}
