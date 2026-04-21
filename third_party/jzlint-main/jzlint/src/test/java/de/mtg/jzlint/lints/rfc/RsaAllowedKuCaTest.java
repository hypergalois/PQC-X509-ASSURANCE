package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RsaAllowedKuCaTest {

    @LintTest(
            name = "e_rsa_allowed_ku_ca",
            filename = "ecdsaP384.pem",
            expectedResultStatus = Status.NA)
    void testCase01() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_ca",
            filename = "eeWithRSAAllowedKeyUsage.pem",
            expectedResultStatus = Status.NA)
    void testCase02() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_ca",
            filename = "caWithRSAAllowedKeyUsageOld.pem",
            expectedResultStatus = Status.NE)
    void testCase03() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_ca",
            filename = "caBasicConstCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_ca",
            filename = "caWithRSADisallowedKeyUsage.pem",
            expectedResultStatus = Status.ERROR,
            expectedResultDetails = "CA certificate with an RSA key contains invalid key usage(s): keyAgreement")
    void testCase05() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_ca",
            filename = "caWithRSAAndEnciphermentKeyUsage.pem",
            expectedResultStatus = Status.PASS)
    void testCase06() {
    }

}