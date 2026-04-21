package de.mtg.jzlint;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class LintTestExtension implements AfterEachCallback, BeforeAllCallback {

    public static final String TESTDATA_DIR = "testdata";
    public static final String CERTIFICATE_TYPE = "X.509";

    @Override
    public void afterEach(ExtensionContext extensionContext) {

        try {
            Method testMethod = extensionContext.getRequiredTestMethod();

            testCertificate(testMethod);

            testCRL(testMethod);

        } catch (Exception ex) {
            fail("An exception occurred", ex);
        }

    }

    private void testCertificate(Method testMethod) throws InvocationTargetException, NoSuchMethodException, IllegalAccessException, InstantiationException {

        LintTest certificateLint = testMethod.getAnnotation(LintTest.class);

        if (certificateLint == null) {
            return;
        }

        X509Certificate certificate;

        Path certificatePath = Paths.get(TESTDATA_DIR, certificateLint.filename());

        if (!Files.exists(certificatePath)) {
            fail(String.format("Could not find certificate %s", certificateLint.filename()));
        }

        try {
            certificate = readTestCertificate(certificatePath);
        } catch (Exception ex) {
            boolean isOK = false;
            if (Status.ERROR == certificateLint.expectedResultStatus() ||
                    Status.WARN == certificateLint.expectedResultStatus() ||
                    Status.PASS == certificateLint.expectedResultStatus()) {
                isOK = true;
            }
            assertTrue(isOK);
            return;
        }
        Runner runner = new Runner();
        LintJSONResult lint = runner.lint(certificate, certificateLint.name());
        assertEquals(LintJSONResult.getResultString(certificateLint.expectedResultStatus()), lint.getResult().toLowerCase());
        String resultString = new LintJSONResults(Arrays.asList(lint)).getResultString();
        assertNotNull(resultString);
        assertFalse(resultString.isEmpty());
        assertTrue(resultString.contains(certificateLint.name()));

    }

    private void testCRL(Method testMethod) throws InvocationTargetException, NoSuchMethodException, IllegalAccessException, InstantiationException {
        LintCRLTest crlLint = testMethod.getAnnotation(LintCRLTest.class);

        if (crlLint == null) {
            return;
        }

        X509CRL crl;

        Path crlPath = Paths.get(TESTDATA_DIR, crlLint.filename());

        if (!Files.exists(crlPath)) {
            fail(String.format("Could not find CRL %s", crlLint.filename()));
        }

        try {
            crl = readTestCRL(crlPath);
        } catch (Exception ex) {
            boolean isOK = false;
            if (Status.ERROR == crlLint.expectedResultStatus() ||
                    Status.WARN == crlLint.expectedResultStatus() ||
                    Status.PASS == crlLint.expectedResultStatus()) {
                isOK = true;
            }
            assertTrue(isOK);
            return;
        }
        Runner runner = new Runner();
        LintJSONResult lint = runner.lint(crl, crlLint.name());
        assertEquals(LintJSONResult.getResultString(crlLint.expectedResultStatus()), lint.getResult().toLowerCase());
        String resultString = new LintJSONResults(Arrays.asList(lint)).getResultString();
        assertNotNull(resultString);
        assertFalse(resultString.isEmpty());
        assertTrue(resultString.contains(crlLint.name()));

    }

    private static X509Certificate readTestCertificate(Path certificatePath) throws CertificateException, IOException, NoSuchProviderException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE, BouncyCastleProvider.PROVIDER_NAME);
        try (InputStream is = Files.newInputStream(certificatePath)) {
            return (X509Certificate) certificateFactory.generateCertificate(is);
        }
    }

    private static X509CRL readTestCRL(Path crlPath) throws IOException, NoSuchProviderException, CRLException, CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE, BouncyCastleProvider.PROVIDER_NAME);
        try (InputStream is = Files.newInputStream(crlPath)) {
            return (X509CRL) certificateFactory.generateCRL(is);
        }
    }

    @Override
    public void beforeAll(ExtensionContext extensionContext) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

}
