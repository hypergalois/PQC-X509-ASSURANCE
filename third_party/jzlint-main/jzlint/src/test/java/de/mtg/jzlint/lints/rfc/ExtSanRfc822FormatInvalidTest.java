package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanRfc822FormatInvalidTest {

    @LintTest(
            name = "e_ext_san_rfc822_format_invalid",
            filename = "SANWithInvalidEmail.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_rfc822_format_invalid",
            filename = "SANWithInvalidEmail2.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_san_rfc822_format_invalid",
            filename = "SANWithValidEmail.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }
}