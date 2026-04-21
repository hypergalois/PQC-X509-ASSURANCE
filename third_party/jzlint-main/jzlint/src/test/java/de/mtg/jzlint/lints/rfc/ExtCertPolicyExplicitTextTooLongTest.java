package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtCertPolicyExplicitTextTooLongTest {

    @LintTest(
            name = "e_ext_cert_policy_explicit_text_too_long",
            filename = "explicitText200Char.pem",
            expectedResultStatus = Status.ERROR)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_cert_policy_explicit_text_too_long",
            filename = "explicitTextBMPString.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_cert_policy_explicit_text_too_long",
            filename = "userNoticeExpTextUtf8.pem",
            expectedResultStatus = Status.PASS)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase03() {
    }
}