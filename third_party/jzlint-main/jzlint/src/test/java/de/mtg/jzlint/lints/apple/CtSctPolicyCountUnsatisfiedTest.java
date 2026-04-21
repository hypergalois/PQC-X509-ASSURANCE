package de.mtg.jzlint.lints.apple;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CtSctPolicyCountUnsatisfiedTest {

    @LintTest(
            name = "w_ct_sct_policy_count_unsatisfied",
            filename = "ctNoSCTsPoisoned.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "No SCTs, poisoned")
    void testCase01() {
    }

    @LintTest(
            name = "w_ct_sct_policy_count_unsatisfied",
            filename = "ctNoSCTs.pem",
            expectedResultStatus = Status.NOTICE,
            certificateDescription = "No SCTs, no poison")
    void testCase02() {
    }

    @LintTest(
            name = "w_ct_sct_policy_count_unsatisfied",
            filename = "ct3mo1SCTs.pem",
            expectedResultStatus = Status.NOTICE,
            certificateDescription = "Lifetime <15mo, 1 SCT")
    void testCase03() {
    }

    @LintTest(
            name = "w_ct_sct_policy_count_unsatisfied",
            filename = "ct3mo2SCTs.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Lifetime <15mo, 2 SCTs diff logs")
    void testCase04() {
    }

    @LintTest(
            name = "w_ct_sct_policy_count_unsatisfied",
            filename = "ct3mo2DupeSCTs.pem",
            expectedResultStatus = Status.NOTICE,
            certificateDescription = "Lifetime <15mo, 2 SCTs same logs")
    void testCase05() {
    }

    @LintTest(
            name = "w_ct_sct_policy_count_unsatisfied",
            filename = "ct18mo2SCTs.pem",
            expectedResultStatus = Status.NOTICE,
            certificateDescription = "Lifetime >15mo <27mo, 2 SCTs diff logs")
    void testCase06() {
    }


    @LintTest(
            name = "w_ct_sct_policy_count_unsatisfied",
            filename = "ct18mo3SCTs.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Lifetime >15mo <27mo, 3 SCTs diff logs")
    void testCase07() {
    }

    @LintTest(
            name = "w_ct_sct_policy_count_unsatisfied",
            filename = "ct38mo3SCTs.pem",
            expectedResultStatus = Status.NOTICE,
            certificateDescription = "Lifetime >27mo <39mo, 3 SCTs diff logs")
    void testCase08() {
    }

    @LintTest(
            name = "w_ct_sct_policy_count_unsatisfied",
            filename = "ct38mo4SCTs.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Lifetime >27mo <39mo, 4 SCTs diff logs")
    void testCase09() {
    }

    @LintTest(
            name = "w_ct_sct_policy_count_unsatisfied",
            filename = "ct666mo4SCTs.pem",
            expectedResultStatus = Status.NOTICE,
            certificateDescription = "Lifetime >39mo, 4 SCTs diff logs")
    void testCase10() {
    }

    @LintTest(
            name = "w_ct_sct_policy_count_unsatisfied",
            filename = "ct666mo5SCTs.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Lifetime >39mo, 5 SCTs diff logs")
    void testCase11() {
    }

}