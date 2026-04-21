package de.mtg.jzlint;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;

import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import picocli.CommandLine;

import de.mtg.jzlint.utils.DateUtils;

@CommandLine.Command(
        name = "jzlint",
        mixinStandardHelpOptions = true,
        version = "1.0",
        description = "Lints a certificate, CRL, or OCSP response with jzlint"
)
public class JZLintCli implements Callable<Integer> {

    @CommandLine.Parameters(index = "0", description = "The certificate, CRL, or OCSP response to lint.")
    private File pkiObject;

    @CommandLine.Parameters(arity = "0..1", index = "1", description = "The issuer of a certificate, CRL, or OCSP response which is linted.")
    private Optional<File> issuer;

    @CommandLine.Option(arity = "0..1", names = {"-includeNames"}, split = ",", description = "Comma-separated names of the lints to use.")
    private List<String> includeNames = new ArrayList<>();

    @CommandLine.Option(arity = "0..1", names = {"-excludeSources"}, split = ",", description = "Comma-separated name of the sources to exclude.")
    private List<String> excludeSources = new ArrayList<>();

    @CommandLine.Option(arity = "0..1", names = {"-includeSources"}, split = ",", description = "Comma-separated name of the sources to include.")
    private List<String> includeSources = new ArrayList<>();

    @CommandLine.Option(arity = "0..1", names = {"-excludeNames"}, split = ",", description = "Comma-separated names of the lints to exclude.")
    private List<String> excludeNames = new ArrayList<>();

    @CommandLine.Option(arity = "0..1", names = "-p", description = "A pretty output format")
    private boolean pretty;

    @Override
    public Integer call() throws Exception {

        byte[] rawPKIObject = Files.readAllBytes(pkiObject.toPath());
        byte[] rawIssuer = null;
        if (issuer.isPresent()) {
            rawIssuer = Files.readAllBytes(issuer.get().toPath());
        }

        LintJSONResults lintResult = lint(rawPKIObject, rawIssuer, includeNames, includeSources, excludeSources, excludeNames);

        if (pretty) {
            System.out.println(lintResult.getResultPrettyString());
        } else {

            System.out.println(lintResult.getResultString());
        }
        return 0;
    }


    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        int result = new CommandLine(new JZLintCli()).execute(args);
        System.exit(result);
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

    private static LintJSONResults lint(
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
        boolean isCertificate = getCertificate(pkiObject) != null;
        boolean isCRL = getCRL(pkiObject) != null;
        boolean isOCSP = getOCSPResponse(pkiObject) != null;

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
                X509Certificate certificate = getCertificate(pkiObject);
                ZonedDateTime time = DateUtils.getNotBefore(certificate);
                if (hasIssuer && isCertificateIssuerLint) {
                    result.add(getLintResult(certificate, getCertificate(issuer), time, X509Certificate.class, lintClass, lintAnnotation));
                } else if (CliUtils.isCertificateLint(lintClass)) {
                    result.add(getLintResult(certificate, null, time, X509Certificate.class, lintClass, lintAnnotation));
                }
            }

            if (isCRL) {
                X509CRL crl = getCRL(pkiObject);
                ZonedDateTime time = DateUtils.getThisUpdate(crl);
                if (hasIssuer && isCRLIssuerLint) {
                    result.add(getLintResult(crl, getCertificate(issuer), time, X509CRL.class, lintClass, lintAnnotation));
                } else if (CliUtils.isCRLLint(lintClass)) {
                    result.add(getLintResult(crl, null, time, X509CRL.class, lintClass, lintAnnotation));
                }
            }

            if (isOCSP) {
                ZonedDateTime time = DateUtils.getProducedAt(OCSPResponse.getInstance(pkiObject));
                if (hasIssuer && isOCSPResponseIssuerLint) {
                    result.add(getLintResult(pkiObject, getCertificate(issuer), time, byte[].class, lintClass, lintAnnotation));
                } else if (CliUtils.isOCSPResponseLint(lintClass)) {
                    result.add(getLintResult(pkiObject, null, time, byte[].class, lintClass, lintAnnotation));
                }
            }
        }

        return new LintJSONResults(result);
    }


    private static LintJSONResult getLintResult(
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
