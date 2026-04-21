package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanUriRelativeTest {

    @LintTest(
            name = "e_ext_san_uri_relative",
            filename = "SANURIRelative.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_uri_relative",
            filename = "SANURIAbsolute.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}