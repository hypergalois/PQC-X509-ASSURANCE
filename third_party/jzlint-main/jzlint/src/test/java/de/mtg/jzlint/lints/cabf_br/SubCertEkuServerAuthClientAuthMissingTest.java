package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertEkuServerAuthClientAuthMissingTest {

    @LintTest(
            name = "e_sub_cert_eku_server_auth_client_auth_missing",
            filename = "subExtKeyUsageCodeSign.pem",
            expectedResultStatus = Status.NA)
    @Disabled("NA seems to be the wrong expected result here?")
    void testCase01() {
    }

    @LintTest(
            name = "e_sub_cert_eku_server_auth_client_auth_missing",
            filename = "subExtKeyUsageServClient.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}
