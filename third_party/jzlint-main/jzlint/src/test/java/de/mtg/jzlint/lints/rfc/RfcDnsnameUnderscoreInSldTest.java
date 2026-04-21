package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class RfcDnsnameUnderscoreInSldTest {

    @LintTest(
            name = "e_rfc_dnsname_underscore_in_sld",
            filename = "dnsNameUnderscoreInSLD.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_rfc_dnsname_underscore_in_sld",
            filename = "dnsNameNoUnderscoreInSLD.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}