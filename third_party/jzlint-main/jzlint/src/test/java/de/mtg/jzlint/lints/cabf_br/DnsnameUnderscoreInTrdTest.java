package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DnsnameUnderscoreInTrdTest {

    @LintTest(
            name = "w_dnsname_underscore_in_trd",
            filename = "dnsNameUnderscoreInTRD.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_dnsname_underscore_in_trd",
            filename = "dnsNameNoUnderscoreInTRD.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }


}