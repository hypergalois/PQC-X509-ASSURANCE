package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RsaFermatFactorizationTest {

    @LintTest(
            name = "e_rsa_fermat_factorization",
            filename = "rsaFermatFactorizationSusceptible.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_rsa_fermat_factorization",
            filename = "rsassapssWithSHA512.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }


}