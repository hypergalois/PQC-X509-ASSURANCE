package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtCertPolicyExplicitTextIncludesControlTest {

    @LintTest(
            name = "w_ext_cert_policy_explicit_text_includes_control",
            filename = "utf8ControlX10.pem",
            expectedResultStatus = Status.WARN)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase01() {
    }

    @LintTest(
            name = "w_ext_cert_policy_explicit_text_includes_control",
            filename = "utf8ControlX88.pem",
            expectedResultStatus = Status.WARN)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase02() {
    }

    @LintTest(
            name = "w_ext_cert_policy_explicit_text_includes_control",
            filename = "utf8NoControl.pem",
            expectedResultStatus = Status.PASS)
    @Disabled("Certificate contains invalid certificate policies extension")
    void testCase03() {
    }

}