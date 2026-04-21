package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubCertSha1ExpirationTooLongTest {

    @LintTest(
            name = "w_sub_cert_sha1_expiration_too_long",
            filename = "sha1ExpireAfter2017.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_sub_cert_sha1_expiration_too_long",
            filename = "sha1ExpirePrior2017.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}