package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtAiaAccessLocationMissingTest {

    @LintTest(
            name = "w_ext_aia_access_location_missing",
            filename = "caIssuerNoHTTPLDAP.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_ext_aia_access_location_missing",
            filename = "caIssuerHTTP.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "w_ext_aia_access_location_missing",
            filename = "caIssuerBlank.pem",
            expectedResultStatus = Status.NA)
    void testCase03() {
    }

}