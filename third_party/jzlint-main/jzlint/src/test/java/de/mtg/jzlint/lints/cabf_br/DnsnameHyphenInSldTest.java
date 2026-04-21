package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DnsnameHyphenInSldTest {

    @LintTest(
            name = "e_dnsname_hyphen_in_sld",
            filename = "dnsNameHyphenBeginningSLD.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_dnsname_hyphen_in_sld",
            filename = "dnsNameHyphenEndingSLD.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_dnsname_hyphen_in_sld",
            filename = "dnsNameWildcardCorrect.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

    @LintTest(
            name = "e_dnsname_hyphen_in_sld",
            filename = "dnsNamePrivatePublicSuffix.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

}