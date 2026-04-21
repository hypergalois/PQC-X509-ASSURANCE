package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class OldRootCaRsaModLessThan2048BitsTest {

    @LintTest(
            name = "e_old_root_ca_rsa_mod_less_than_2048_bits",
            filename = "oldRootModTooSmall.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_old_root_ca_rsa_mod_less_than_2048_bits",
            filename = "oldRootModSmall.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}