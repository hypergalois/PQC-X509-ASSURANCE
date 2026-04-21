package de.mtg.jlintocsp.lints.rfc;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlintocsp.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class OcspLintCorrectResponseStatusTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void passTest() {
        byte[] correctResponse = caExtension.getCorrectResponse();
        caExtension.assertLintResult(LintResult.of(Status.PASS), true, new OcspLintCorrectResponseStatus(), correctResponse);
    }

    @Test
    void errorTest() throws NoSuchAlgorithmException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException {
        byte[] response = caExtension.createOCSPResponse(42);
        caExtension.assertLintResult(LintResult.of(Status.ERROR), true, new OcspLintCorrectResponseStatus(), response);
    }

}
