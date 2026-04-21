package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;


@ExtendWith(LintTestExtension.class)
class RsaExpNegativeTest {

    @LintTest(
            name = "e_rsa_exp_negative",
            filename = "IANURIValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

}