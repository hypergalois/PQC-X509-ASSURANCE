package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RfcDnsNameEmptyLabelTest {

    @LintTest(
            name = "e_ext_cert_policy_duplicate",
            filename = "certPolicyDuplicateShort.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_cert_policy_duplicate",
            filename = "certPolicyAssertionDuplicated.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_cert_policy_duplicate",
            filename = "certPolicyNoDuplicate.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

}