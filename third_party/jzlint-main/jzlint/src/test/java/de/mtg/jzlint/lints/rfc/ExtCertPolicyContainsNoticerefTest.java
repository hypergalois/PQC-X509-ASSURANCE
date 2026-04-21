package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtCertPolicyContainsNoticerefTest {
    @LintTest(
            name = "w_ext_cert_policy_contains_noticeref",
            filename = "userNoticePres.pem",
            expectedResultStatus = Status.WARN)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase01() {
    }

    @LintTest(
            name = "w_ext_cert_policy_contains_noticeref",
            filename = "userNoticeMissing.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}