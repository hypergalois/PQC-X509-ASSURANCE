package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertValidTimeLongerThan39MonthsTest {

    @LintTest(
            name = "e_sub_cert_valid_time_longer_than_39_months",
            filename = "subCertValidTimeTooLong.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_valid_time_longer_than_39_months",
            filename = "subCertValidTimeGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_sub_cert_valid_time_longer_than_39_months",
            filename = "39months.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

}
