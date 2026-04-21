package de.mtg.jzlint.lints.mozilla;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MpAllowedEkuTest {

    @LintTest(
            name = "n_mp_allowed_eku",
            filename = "mpSubCAEKUDisallowed1.pem",
            expectedResultStatus = Status.NOTICE,
            certificateDescription = "SubCA with no EKU")
    void testCase01() {
    }

    @LintTest(
            name = "n_mp_allowed_eku",
            filename = "mpSubCAEKUDisallowed2.pem",
            expectedResultStatus = Status.NOTICE,
            certificateDescription = "SubCA with anyExtendedKeyUsage")
    void testCase02() {
    }

    @LintTest(
            name = "n_mp_allowed_eku",
            filename = "mpSubCAEKUDisallowed3.pem",
            expectedResultStatus = Status.NOTICE,
            certificateDescription = "SubCA with serverAuth and emailProtection")
    void testCase03() {
    }

    @LintTest(
            name = "n_mp_allowed_eku",
            filename = "mpSubCAEKUAllowed.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "SubCA with serverAuth EKU")
    void testCase04() {
    }

    @LintTest(
            name = "n_mp_allowed_eku",
            filename = "mpCrossCertNoEKU.pem",
            expectedResultStatus = Status.NOTICE,
            certificateDescription = "Cross-Certificate with no EKU")
    void testCase05() {
    }

}