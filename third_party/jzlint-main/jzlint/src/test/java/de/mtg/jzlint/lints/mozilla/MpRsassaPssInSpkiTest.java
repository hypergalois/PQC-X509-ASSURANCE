package de.mtg.jzlint.lints.mozilla;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class MpRsassaPssInSpkiTest {

    @LintTest(
            name = "e_mp_rsassa-pss_in_spki",
            filename = "rsassapssWithSHA256.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Correct certificate without RSASSA-PSS OID in public key")
    void testCase01() {
    }

    @LintTest(
            name = "e_mp_rsassa-pss_in_spki",
            filename = "rsassapssInSPKI.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Certificate with RSASSA-PSS OID in public key")
    void testCase02() {
    }
}