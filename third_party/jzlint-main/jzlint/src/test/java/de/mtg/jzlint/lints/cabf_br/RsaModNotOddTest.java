package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RsaModNotOddTest {
    @LintTest(
            name = "w_rsa_mod_not_odd",
            filename = "oddRsaMod.pem",
            expectedResultStatus = Status.PASS)
    @Disabled("java.lang.IllegalArgumentException: RSA modulus is even")
    void testCase01() {
    }


    @LintTest(
            name = "w_rsa_mod_not_odd",
            filename = "evenRsaMod.pem",
            expectedResultStatus = Status.WARN)
    @Disabled("java.lang.IllegalArgumentException: RSA modulus has a small prime factor")
    void testCase02() {
    }

}