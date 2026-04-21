package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubscribersCrlDistributionPointsAreHttpTest {
    
    @LintTest(
            name = "e_subscribers_crl_distribution_points_are_http",
            filename = "smime/strict_subscriber_with_http_crl_distribution_point.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - strict cert with only HTTP CRL distribution points")
    void testCase01() {
    }

    @LintTest(
            name = "e_subscribers_crl_distribution_points_are_http",
            filename = "smime/strict_subscriber_with_non_http_crl_distribution_point.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - strict cert with a non-HTTP CRL distribution point")
    void testCase02() {
    }

    @LintTest(
            name = "e_subscribers_crl_distribution_points_are_http",
            filename = "smime/legacy_subscriber_with_non_http_crl_distribution_point.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - legacy cert with no HTTP CRL distribution points")
    void testCase03() {
    }

    @LintTest(
            name = "e_subscribers_crl_distribution_points_are_http",
            filename = "smime/legacy_subscriber_with_mixed_crl_distribution_points.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - legacy cert with HTTP and non-HTTP CRL distribution points")
    void testCase04() {
    }

    @LintTest(
            name = "e_subscribers_crl_distribution_points_are_http",
            filename = "smime/strict_subscriber_with_mixed_crl_distribution_points.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - strict cert with HTTP and non-HTTP CRL distribution points")
    void testCase05() {
    }

}
