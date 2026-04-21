package de.mtg.jzlint.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.mtg.jzlint.IneffectiveDate;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintClassesContainer;
import de.mtg.jzlint.LintJSONResult;
import de.mtg.jzlint.LintJSONResults;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.DateUtils;

public final class ServerUtils {

    public static LintResponse convertResultToResponse(final LintJSONResults results) {
        Set<String> keySet = results.getResult().keySet();
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        LintResponse lintResponse = new LintResponse();
        for (String key : keySet) {
            String result = results.getResult().get(key).get("result");
            if ("error".equalsIgnoreCase(result)) {
                errors.add(key);
            }
            if ("warning".equalsIgnoreCase(result)) {
                warnings.add(key);
            }
        }
        lintResponse.setErrors(errors);
        lintResponse.setWarnings(warnings);
        return lintResponse;
    }


    public static X509Certificate getCertificate(byte[] input) {
        try (InputStream inputStream = new ByteArrayInputStream(input)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } catch (IOException | CertificateException | NoSuchProviderException ex) {
            return null;
        }
    }

    public static X509CRL getCRL(byte[] input) {
        try (InputStream inputStream = new ByteArrayInputStream(input)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
            return (X509CRL) certificateFactory.generateCRL(inputStream);
        } catch (IOException | CertificateException | NoSuchProviderException | CRLException ex) {
            return null;
        }
    }

    public static OCSPResponse getOCSPResponse(byte[] input) {
        try {
            return OCSPResponse.getInstance(input);
        } catch (Exception ex) {
            return null;
        }
    }

    public static LintJSONResults lint(
            byte[] pkiObject,
            byte[] issuer,
            List<String> includeNames,
            List<String> includeSources,
            List<String> excludeSources,
            List<String> excludeNames) throws NoSuchMethodException, IllegalAccessException, InstantiationException, InvocationTargetException {

        LintClassesContainer lintClassesContainer = LintClassesContainer.getInstance();
        List<Class<?>> lintClasses = lintClassesContainer.getLintClasses();

        List<LintJSONResult> result = new ArrayList<>();

        boolean hasIssuer = (issuer != null && issuer.length > 0);
        X509Certificate certificate = getCertificate(pkiObject);
        X509CRL crl = getCRL(pkiObject);
        boolean isCertificate = certificate != null;
        boolean isCRL = crl != null;
        OCSPResponse ocspResponse = getOCSPResponse(pkiObject);
        boolean isOCSP = ocspResponse != null;
        X509Certificate issuerCertificate = null;
        if (hasIssuer) {
            issuerCertificate = getCertificate(issuer);
        }

        for (Class<?> lintClass : lintClasses) {

            if (!lintClass.isAnnotationPresent(Lint.class)) {
                continue;
            }

            Lint lintAnnotation = lintClass.getAnnotation(Lint.class);

            String lintName = lintAnnotation.name();

            if (includeNames != null && !includeNames.isEmpty() && !includeNames.contains(lintName)) {
                continue;
            }

            if (excludeNames != null && !excludeNames.isEmpty() && excludeNames.contains(lintName)) {
                continue;
            }

            Source source = lintAnnotation.source();
            if (!CliUtils.includeLint(source, includeSources, excludeSources)) {
                continue;
            }

            boolean isCertificateIssuerLint = CliUtils.isCertificateIssuerLint(lintClass);
            boolean isCRLIssuerLint = CliUtils.isCRLIssuerLint(lintClass);
            boolean isOCSPResponseIssuerLint = CliUtils.isOCSPResponseIssuerLint(lintClass);

            if (isCertificate) {
                ZonedDateTime time = DateUtils.getNotBefore(certificate);
                if (hasIssuer && isCertificateIssuerLint) {
                    result.add(getLintResult(certificate, issuerCertificate, time, X509Certificate.class, lintClass, lintAnnotation));
                } else if (CliUtils.isCertificateLint(lintClass)) {
                    result.add(getLintResult(certificate, null, time, X509Certificate.class, lintClass, lintAnnotation));
                }
            }

            if (isCRL) {
                ZonedDateTime time = DateUtils.getThisUpdate(crl);
                if (hasIssuer && isCRLIssuerLint) {
                    result.add(getLintResult(crl, issuerCertificate, time, X509CRL.class, lintClass, lintAnnotation));
                } else if (CliUtils.isCRLLint(lintClass)) {
                    result.add(getLintResult(crl, null, time, X509CRL.class, lintClass, lintAnnotation));
                }
            }

            if (isOCSP) {
                ZonedDateTime time = DateUtils.getProducedAt(ocspResponse);
                if (hasIssuer && isOCSPResponseIssuerLint) {
                    result.add(getLintResult(pkiObject, issuerCertificate, time, byte[].class, lintClass, lintAnnotation));
                } else if (CliUtils.isOCSPResponseLint(lintClass)) {
                    result.add(getLintResult(pkiObject, null, time, byte[].class, lintClass, lintAnnotation));
                }
            }
        }

        return new LintJSONResults(result);
    }


    public static LintJSONResult getLintResult(
            Object pkiObject,
            X509Certificate issuer,
            ZonedDateTime time,
            Class<?> pkiObjectClass,
            Class<?> lintClass,
            Lint lintAnnotation) throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {

        Method checkAppliesMethod;
        Method executeMethod;
        if (issuer == null) {
            checkAppliesMethod = lintClass.getMethod(CliUtils.CHECK_APPLIES, pkiObjectClass);
            executeMethod = lintClass.getMethod(CliUtils.EXECUTE, pkiObjectClass);
        } else {
            checkAppliesMethod = lintClass.getMethod(CliUtils.CHECK_APPLIES, pkiObjectClass, issuer.getClass());
            executeMethod = lintClass.getMethod(CliUtils.EXECUTE, pkiObjectClass, issuer.getClass());
        }

        Object object = lintClass.getDeclaredConstructor().newInstance();

        boolean checkApplies;
        if (issuer == null) {
            checkApplies = (boolean) checkAppliesMethod.invoke(object, pkiObject);
        } else {
            checkApplies = (boolean) checkAppliesMethod.invoke(object, pkiObject, issuer);
        }

        if (!checkApplies) {
            return new LintJSONResult(lintAnnotation.name(), Status.NA);
        }

        if (!DateUtils.isIssuedOnOrAfter(time, lintAnnotation.effectiveDate().getZonedDateTime())) {
            return new LintJSONResult(lintAnnotation.name(), Status.NE);
        }

        if (IneffectiveDate.EMPTY != lintAnnotation.ineffectiveDate() &&
                DateUtils.isIssuedOnOrAfter(time, lintAnnotation.ineffectiveDate().getZonedDateTime())) {
            return new LintJSONResult(lintAnnotation.name(), Status.NE);
        }

        LintResult lintResult;
        if (issuer == null) {
            lintResult = (LintResult) executeMethod.invoke(object, pkiObject);
        } else {
            lintResult = (LintResult) executeMethod.invoke(object, pkiObject, issuer);
        }

        return new LintJSONResult(lintAnnotation.name(), lintResult.getStatus());

    }

}
