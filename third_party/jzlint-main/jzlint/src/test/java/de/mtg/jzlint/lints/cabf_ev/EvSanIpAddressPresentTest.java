package de.mtg.jzlint.lints.cabf_ev;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EvSanIpAddressPresentTest {

    @LintTest(
            name = "e_ev_san_ip_address_present",
            filename = "evSanIpAddressPresent.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ev_san_ip_address_present",
            filename = "evAllGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}