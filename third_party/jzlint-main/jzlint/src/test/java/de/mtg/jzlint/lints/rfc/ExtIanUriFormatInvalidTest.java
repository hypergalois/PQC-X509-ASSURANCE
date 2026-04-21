package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtIanUriFormatInvalidTest {

    @LintTest(
            name = "e_ext_ian_uri_format_invalid",
            filename = "IANURIValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_ian_uri_format_invalid",
            filename = "IANURINoScheme.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_ian_uri_format_invalid",
            filename = "IANURINoSchemeSpecificPart.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

}
