package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertCrlDistributionPointsDoesNotContainUrlTest {

    @LintTest(
            name = "e_sub_cert_crl_distribution_points_does_not_contain_url",
            filename = "subCrlDistNoURL.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_crl_distribution_points_does_not_contain_url",
            filename = "subCrlDistURL.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_sub_cert_crl_distribution_points_does_not_contain_url",
            filename = "subCrlDistURLInCompoundFullName.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

}