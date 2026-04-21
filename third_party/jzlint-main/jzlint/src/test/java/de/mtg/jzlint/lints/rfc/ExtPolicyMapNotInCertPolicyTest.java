package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtPolicyMapNotInCertPolicyTest {

    @LintTest(
            name = "w_ext_policy_map_not_in_cert_policy",
            filename = "policyMapIssuerNotInCertPolicy.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_ext_policy_map_not_in_cert_policy",
            filename = "policyMapGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}