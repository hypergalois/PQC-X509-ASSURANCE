package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EcdsaEeInvalidKuTest {

    @LintTest(
            name = "n_ecdsa_ee_invalid_ku",
            filename = "rsaKeyWithParameters.pem",
            expectedResultStatus = Status.NA)
    void testCase01() {
    }

    @LintTest(
            name = "n_ecdsa_ee_invalid_ku",
            filename = "ecdsaP256ValidKUs.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "n_ecdsa_ee_invalid_ku",
            filename = "ecdsaP384InvalidKUs.pem",
            expectedResultStatus = Status.NOTICE)
    void testCase03() {
    }

    @LintTest(
            name = "n_ecdsa_ee_invalid_ku",
            filename = "ecdsaP256.pem",
            expectedResultStatus = Status.NOTICE)
    void testCase04() {
    }

    @LintTest(
            name = "n_ecdsa_ee_invalid_ku",
            filename = "CNWithoutSANSeptember2021.pem",
            expectedResultStatus = Status.NA)
    @Disabled("This certificate cannot be parsed by bouncy castle.")
    void testCase05() {
    }

}
