package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubscribersShallHaveCrlDistributionPointsTest {

    @LintTest(
            name = "e_subscribers_shall_have_crl_distribution_points",
            filename = "smime/subscriber_with_crl_distribution_points.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - cert with a CRL distribution point")
    void testCase01() {
    }

    @LintTest(
            name = "e_subscribers_shall_have_crl_distribution_points",
            filename = "smime/subscriber_no_crl_distribution_points.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - cert without a CRL distribution point")
    void testCase02() {
    }

    @LintTest(
            name = "e_subscribers_shall_have_crl_distribution_points",
            filename = "smime/with_subject_alternative_name_no_br.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "na - certificate has no SMIME BR policy")
    void testCase03() {
    }


}
