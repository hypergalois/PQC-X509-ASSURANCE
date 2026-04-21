package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtPolicyMapAnyPolicyTest {

    @LintTest(
            name = "e_ext_policy_map_any_policy",
            filename = "policyMapFromAnyPolicy.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_policy_map_any_policy",
            filename = "policyMapToAnyPolicy.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_policy_map_any_policy",
            filename = "policyMapGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

}