package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class PolicyQualifiersOtherThanCpsNotPermittedTest {

    @LintTest(
            name = "e_policy_qualifiers_other_than_cps_not_permitted",
            filename = "policyQualifiersOtherThanCpsNotPermittedValid.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Valid")
    void testCase01() {
    }

    @LintTest(
            name = "e_policy_qualifiers_other_than_cps_not_permitted",
            filename = "policyQualifiersOtherThanCpsNotPermittedError.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Error")
    @Disabled("This certificate cannot be parsed by Java/BouncyCastle")
    void testCase02() {
    }

    @LintTest(
            name = "e_policy_qualifiers_other_than_cps_not_permitted",
            filename = "policyQualifiersOtherThanCpsNotPermittedNotApplicable.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "Not Applicable")
    @Disabled("This certificate cannot be parsed by Java/BouncyCastle")
    void testCase03() {
    }

}