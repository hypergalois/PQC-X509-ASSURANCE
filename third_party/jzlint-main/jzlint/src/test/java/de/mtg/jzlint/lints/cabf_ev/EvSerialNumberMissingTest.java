package de.mtg.jzlint.lints.cabf_ev;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EvSerialNumberMissingTest {

    @LintTest(
            name = "e_ev_serial_number_missing",
            filename = "evAllGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_ev_serial_number_missing",
            filename = "evNoSN.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}