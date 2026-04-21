package de.mtg.jzlint.lints.apple;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class TlsServerCertValidTimeLongerThan398DaysTest {

    @LintTest(
            name = "e_tls_server_cert_valid_time_longer_than_398_days",
            filename = "eeServerCertValidOver398OldNotBefore.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "Cert issued before Sept 1, 2020 lifetime > 398 days")
    void testCase01() {
    }

    @LintTest(
            name = "e_tls_server_cert_valid_time_longer_than_398_days",
            filename = "eeServerCertValidEqual397.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Cert issued after Sept 1, 2020 with lifetime <= 397 days")
    void testCase02() {
    }

    @LintTest(
            name = "e_tls_server_cert_valid_time_longer_than_398_days",
            filename = "eeServerCertValidOver397.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Cert issued after Sept 1, 2020 with lifetime > 397 and < 398 days")
    void testCase03() {
    }

    @LintTest(
            name = "e_tls_server_cert_valid_time_longer_than_398_days",
            filename = "eeServerCertValidEqual398.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Cert issued after Sept 1, 2020 with lifetime == 398 days")
    void testCase04() {
    }


    @LintTest(
            name = "e_tls_server_cert_valid_time_longer_than_398_days",
            filename = "eeServerCertValidOver398.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Cert issued after Sept 1, 2020 with lifetime > 398 days")
    void testCase05() {
    }

    @LintTest(
            name = "e_tls_server_cert_valid_time_longer_than_398_days",
            filename = "caBasicConstCrit.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "Cert containing CA basic constraint, should be Not Applicable")
    void testCase06() {
    }
}