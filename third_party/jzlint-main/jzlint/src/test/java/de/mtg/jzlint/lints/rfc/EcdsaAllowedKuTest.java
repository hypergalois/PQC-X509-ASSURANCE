package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EcdsaAllowedKuTest {

    @LintTest(
            name = "e_ecdsa_allowed_ku",
            filename = "rsaKeyWithParameters.pem",
            expectedResultStatus = Status.NA)
    void testCase01() {
    }

    @LintTest(
            name = "e_ecdsa_allowed_ku",
            filename = "ecdsaP256ValidKUs.pem",
            expectedResultStatus = Status.NE)
    void testCase02() {
    }

    @LintTest(
            name = "e_ecdsa_allowed_ku",
            filename = "ecdsaP256AbsentKU.pem",
            expectedResultStatus = Status.NA)
    void testCase03() {
    }

    @LintTest(
            name = "e_ecdsa_allowed_ku",
            filename = "ecdsaP256KUIsDigitalSignatureValidKU.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

    @LintTest(
            name = "e_ecdsa_allowed_ku",
            filename = "ecdsaP256KUIsDataEnciphermentInvalidKU.pem",
            expectedResultStatus = Status.ERROR,
            expectedResultDetails = "Certificate contains invalid key usage(s): dataEncipherment")
    void testCase05() {
    }

    @LintTest(
            name = "e_ecdsa_allowed_ku",
            filename = "ecdsaP256KUIsKeyEnciphermentInvalidKU.pem",
            expectedResultStatus = Status.ERROR,
            expectedResultDetails = "Certificate contains invalid key usage(s): keyEncipherment")
    void testCase06() {
    }

    @LintTest(
            name = "e_ecdsa_allowed_ku",
            filename = "ecdsaP256KUIsKeyEnciphermentAndDataEnciphermentInvalidKU.pem",
            expectedResultStatus = Status.ERROR,
            expectedResultDetails = "Certificate contains invalid key usage(s): keyEncipherment, dataEncipherment")
    void testCase07() {
    }
}