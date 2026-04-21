package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtCertPolicyDisallowedAnyPolicyQualifierTest {

    @LintTest(
            name = "e_ext_cert_policy_disallowed_any_policy_qualifier",
            filename = "withoutAnyPolicy.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "Certificate with certificate policies extension and without the anyPolicy policyIdentifier present")
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_cert_policy_disallowed_any_policy_qualifier",
            filename = "CNWithoutSANSeptember2021.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "Certificate without certificate policies extension")
    @Disabled("java.lang.IllegalArgumentException: empty extension sequence found")
    void testCase02() {
    }

    @LintTest(
            name = "e_ext_cert_policy_disallowed_any_policy_qualifier",
            filename = "withAnyPolicyAndNoPolicyQualifiers.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Certificate with certificate policies extension, with anyPolicy policyIdentifier present, without policyQualifiers")
    void testCase03() {
    }

    @LintTest(
            name = "e_ext_cert_policy_disallowed_any_policy_qualifier",
            filename = "withAnyPolicyAndCPSQualifier.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Certificate with certificate policies extension, with anyPolicy policyIdentifier present and a CPS qualifier present")
    void testCase04() {
    }

    @LintTest(
            name = "e_ext_cert_policy_disallowed_any_policy_qualifier",
            filename = "withAnyPolicyAndUserNoticeQualifier.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Certificate with certificate policies extension, with anyPolicy policyIdentifier present and a UserNotice qualifier present")
    void testCase05() {
    }

    @LintTest(
            name = "e_ext_cert_policy_disallowed_any_policy_qualifier",
            filename = "withAnyPolicyWithoutCPSOrUserNoticeQualifier.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Certificate with certificate policies extension, with anyPolicy policyIdentifier present and neither CPS nor UserNotice qualifier present")
    void testCase06() {
    }

    @LintTest(
            name = "e_ext_cert_policy_disallowed_any_policy_qualifier",
            filename = "withValidPoliciesRegardingAnyPolicy.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Certificate with certificate policies extension and many combinations of policies and qualifiers")
    void testCase07() {
    }

}