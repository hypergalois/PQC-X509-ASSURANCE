package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EcImproperCurvesTest {

    @LintTest(
            name = "e_ec_improper_curves",
            filename = "ecdsaP224.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ec_improper_curves",
            filename = "ecdsaP256.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_ec_improper_curves",
            filename = "ecdsaP384.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

    @LintTest(
            name = "e_ec_improper_curves",
            filename = "ecdsaP521.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }
}