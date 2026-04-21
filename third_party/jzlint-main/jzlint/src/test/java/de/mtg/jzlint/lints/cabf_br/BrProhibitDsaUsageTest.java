package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class BrProhibitDsaUsageTest {

    @LintTest(
            name = "e_br_prohibit_dsa_usage",
            filename = "ecc256_post_br_1_7_1.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Certificate using ECC and P-256")
    void testCase01() {
    }

    @LintTest(
            name = "e_br_prohibit_dsa_usage",
            filename = "dsaCorrectOrderInSubgroup.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "Certificate using DSA where lint does not apply")
    void testCase02() {
    }

    @LintTest(
            name = "e_br_prohibit_dsa_usage",
            filename = "dsaCert.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Certificate using DSA where lint applies")
    void testCase03() {
    }
}