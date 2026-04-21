package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CrlissuerMustNotBePresentInCdpTest {

    @LintTest(
            name = "e_crlissuer_must_not_be_present_in_cdp",
            filename = "crlIssuerMustNotBePresent_error.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_crlissuer_must_not_be_present_in_cdp",
            filename = "crlIssuerMustNotBePresent_pass.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }


    @LintTest(
            name = "e_crlissuer_must_not_be_present_in_cdp",
            filename = "crlIssuerMustNotBePresent_NA.pem",
            expectedResultStatus = Status.NA)
    void testCase03() {
    }

}
