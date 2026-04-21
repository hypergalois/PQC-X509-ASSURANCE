package de.mtg.jlintocsp.lints.rfc;

import java.security.cert.CertificateEncodingException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlintocsp.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class OcspLintResponseWellFormedTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void passTest() {
        byte[] correctResponse = caExtension.getCorrectResponse();
        caExtension.assertLintResult(LintResult.of(Status.PASS), true, new OcspLintResponseWellFormed(), correctResponse);
    }

    @Test
    void errorTest() throws CertificateEncodingException {
        byte[] response = caExtension.getCaCertificate().getEncoded();
        caExtension.assertLintResult(LintResult.of(Status.ERROR), true, new OcspLintResponseWellFormed(), response);
    }

}
