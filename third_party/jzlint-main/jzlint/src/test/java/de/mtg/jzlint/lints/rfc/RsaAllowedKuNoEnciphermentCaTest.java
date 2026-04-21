package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RsaAllowedKuNoEnciphermentCaTest {

    @LintTest(
            name = "e_rsa_allowed_ku_no_encipherment_ca",
            filename = "ecdsaP384.pem",
            expectedResultStatus = Status.NA)
    void testCase01() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_no_encipherment_ca",
            filename = "eeWithRSAAllowedKeyUsage.pem",
            expectedResultStatus = Status.NA)
    void testCase02() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_no_encipherment_ca",
            filename = "caWithRSAAllowedKeyUsageOld.pem",
            expectedResultStatus = Status.NE)
    void testCase03() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_no_encipherment_ca",
            filename = "caBasicConstCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_no_encipherment_ca",
            filename = "caWithRSAAndEnciphermentKeyUsage.pem",
            expectedResultStatus = Status.ERROR,
            expectedResultDetails = "CA certificate with an RSA key and key usage keyCertSign and/or cRLSign has additionally keyEncipherment and/or dataEncipherment key usage")
    void testCase05() {
    }

}