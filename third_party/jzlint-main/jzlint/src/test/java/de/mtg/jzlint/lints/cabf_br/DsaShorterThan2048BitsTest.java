package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DsaShorterThan2048BitsTest {

    @LintTest(
            name = "e_dsa_shorter_than_2048_bits",
            filename = "dsaShorterThan2048Bits.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_dsa_shorter_than_2048_bits",
            filename = "dsaNotShorterThan2048Bits.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}