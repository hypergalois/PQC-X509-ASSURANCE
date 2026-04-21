package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtCertPolicyExplicitTextNotNfcTest {

    @LintTest(
            name = "w_ext_cert_policy_explicit_text_not_nfc",
            filename = "userNoticeExpTextUtf8.pem",
            expectedResultStatus = Status.PASS)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase01() {
    }

    @LintTest(
            name = "w_ext_cert_policy_explicit_text_not_nfc",
            filename = "explicitTextUtf8NotNFC.pem",
            expectedResultStatus = Status.WARN)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase02() {
    }

    @LintTest(
            name = "w_ext_cert_policy_explicit_text_not_nfc",
            filename = "explicitTextBMPNFC.pem",
            expectedResultStatus = Status.PASS)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase03() {
    }

    @LintTest(
            name = "w_ext_cert_policy_explicit_text_not_nfc",
            filename = "explicitTextBMPNotNFC.pem",
            expectedResultStatus = Status.WARN)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase04() {
    }

}