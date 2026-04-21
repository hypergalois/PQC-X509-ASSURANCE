package de.mtg.jlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.lints.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class IssuerGivenNameMaxLengthTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void naTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createNACertificate(caExtension);
        caExtension.assertLintResult(LintResult.of(Status.NA), new IssuerGivenNameMaxLength(), certificate);
    }

    @Test
    void passTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createMaximumLengthCertificate(caExtension);
        caExtension.assertLintResult(LintResult.of(Status.PASS), new IssuerGivenNameMaxLength(), certificate);
    }

    @Test
    void errorTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createExceedingMaximumLengthCertificate(caExtension);
        caExtension.assertLintResult(LintResult.of(Status.ERROR), new IssuerGivenNameMaxLength(), certificate);
    }

}
