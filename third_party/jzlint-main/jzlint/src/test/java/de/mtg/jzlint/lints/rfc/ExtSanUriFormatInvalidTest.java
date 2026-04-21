package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanUriFormatInvalidTest {

    @LintTest(
            name = "e_ext_san_uri_format_invalid",
            filename = "SANURIValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_uri_format_invalid",
            filename = "SANURINoScheme.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_san_uri_format_invalid",
            filename = "SANURINoSchemeSpecificPart.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

}