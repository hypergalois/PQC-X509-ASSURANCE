package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertValidTimeLongerThan825DaysTest {

    @LintTest(
            name = "e_sub_cert_valid_time_longer_than_825_days",
            filename = "subCertOver825DaysBad.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_valid_time_longer_than_825_days",
            filename = "subCertOver825DaysOK.pem",
            expectedResultStatus = Status.NE)
    void testCase02() {
    }

    @LintTest(
            name = "e_sub_cert_valid_time_longer_than_825_days",
            filename = "subCert825DaysOK.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

}