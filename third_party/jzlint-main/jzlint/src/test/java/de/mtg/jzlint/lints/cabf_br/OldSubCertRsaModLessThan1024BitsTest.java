package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class OldSubCertRsaModLessThan1024BitsTest {

    @LintTest(
            name = "e_old_sub_cert_rsa_mod_less_than_1024_bits",
            filename = "oldSubTooSmall.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_old_sub_cert_rsa_mod_less_than_1024_bits",
            filename = "oldSubSmall.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}