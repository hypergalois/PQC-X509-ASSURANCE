package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtCertPolicyExplicitTextIa5StringTest {

    @LintTest(
            name = "e_ext_cert_policy_explicit_text_ia5_string",
            filename = "userNoticePres.pem",
            expectedResultStatus = Status.ERROR)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_cert_policy_explicit_text_ia5_string",
            filename = "userNoticeExpTextNotIA5String.pem",
            expectedResultStatus = Status.ERROR)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_cert_policy_explicit_text_ia5_string",
            filename = "userNoticeMissing.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

    @LintTest(
            name = "e_ext_cert_policy_explicit_text_ia5_string",
            filename = "userNoticeUnrecommended.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

}