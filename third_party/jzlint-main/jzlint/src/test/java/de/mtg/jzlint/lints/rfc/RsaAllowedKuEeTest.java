package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RsaAllowedKuEeTest {

    @LintTest(
            name = "e_rsa_allowed_ku_ee",
            filename = "ecdsaP384.pem",
            expectedResultStatus = Status.NA)
    void testCase01() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_ee",
            filename = "eeWithRSAAllowedKeyUsage.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_ee",
            filename = "caBasicConstCrit.pem",
            expectedResultStatus = Status.NA)
    void testCase03() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_ee",
            filename = "eeWithRSAAllowedKeyUsageOld.pem",
            expectedResultStatus = Status.NE)
    void testCase04() {
    }

    @LintTest(
            name = "e_rsa_allowed_ku_ee",
            filename = "eeWithRSADisallowedKeyUsage.pem",
            expectedResultStatus = Status.ERROR,
            expectedResultDetails = "Subscriber certificate with an RSA key contains invalid key usage(s): keyAgreement")
    void testCase05() {
    }

}