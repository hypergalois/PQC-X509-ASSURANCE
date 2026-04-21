package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class KeyUsageIncorrectLengthTest {

    @LintTest(
            name = "e_key_usage_incorrect_length",
            filename = "incorrect_ku_length.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_key_usage_incorrect_length",
            filename = "facebookOnionV3Address.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}