package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RsaPublicExponentNotOddTest {

    @LintTest(
            name = "e_rsa_public_exponent_not_odd",
            filename = "badRsaExp.pem",
            expectedResultStatus = Status.ERROR)
    @Disabled("java.lang.IllegalArgumentException: RSA publicExponent is even")
    void testCase01() {
    }

    @LintTest(
            name = "e_rsa_public_exponent_not_odd",
            filename = "goodRsaExp.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}