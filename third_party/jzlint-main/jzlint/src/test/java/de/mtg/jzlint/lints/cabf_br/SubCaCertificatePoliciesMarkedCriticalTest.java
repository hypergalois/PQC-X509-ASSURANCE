package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCaCertificatePoliciesMarkedCriticalTest {

    @LintTest(
            name = "w_sub_ca_certificate_policies_marked_critical",
            filename = "subCAWCertPolicyCrit.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_sub_ca_certificate_policies_marked_critical",
            filename = "subCAWCertPolicyNoCrit.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}