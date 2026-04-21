package de.mtg.jzlint.lints.mozilla;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MpExponentCannotBeOneTest {

    @LintTest(
            name = "e_mp_exponent_cannot_be_one",
            filename = "mpExponent1.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Certificate with exponent equal to 0x1")
    void testCase01() {
    }

    @LintTest(
            name = "e_mp_exponent_cannot_be_one",
            filename = "mpExponent10001.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Certificate with exponent equal to 0x10001")
    void testCase02() {
    }

}