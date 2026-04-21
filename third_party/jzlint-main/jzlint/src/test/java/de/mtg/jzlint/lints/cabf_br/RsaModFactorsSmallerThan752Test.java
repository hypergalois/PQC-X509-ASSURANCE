package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RsaModFactorsSmallerThan752Test {

    @LintTest(
            name = "w_rsa_mod_factors_smaller_than_752",
            filename = "evenRsaMod.pem",
            expectedResultStatus = Status.WARN)
    @Disabled("java.lang.IllegalArgumentException: RSA modulus is even")
    void testCase01() {
    }

    @LintTest(
            name = "w_rsa_mod_factors_smaller_than_752",
            filename = "goodRsaExp.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}