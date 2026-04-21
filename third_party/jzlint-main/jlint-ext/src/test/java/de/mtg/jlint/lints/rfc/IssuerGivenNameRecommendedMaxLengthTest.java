package de.mtg.jlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.lints.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class IssuerGivenNameRecommendedMaxLengthTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void naTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createNACertificate(caExtension);
        caExtension.assertLintResult(LintResult.of(Status.NA), new IssuerGivenNameRecommendedMaxLength(), certificate);
    }

    @Test
    void passTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createMaximumLengthCertificate(caExtension, 2, 2, 2, 16, 2, 2, 2, 2, 2, 2, 2, false);
        caExtension.assertLintResult(LintResult.of(Status.PASS), new IssuerGivenNameRecommendedMaxLength(), certificate);
    }

    @Test
    void errorTest() throws Exception {
        X509Certificate certificate = IssuerCommonNameMaxLengthTest.createMaximumLengthCertificate(caExtension, 2, 2, 2, 17, 2, 2, 2, 2, 2, 2, 2, false);
        caExtension.assertLintResult(LintResult.of(Status.WARN), new IssuerGivenNameRecommendedMaxLength(), certificate);
    }

}
