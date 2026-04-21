package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DnsnameNotValidTldTest {

    @LintTest(
            name = "e_dnsname_not_valid_tld",
            filename = "dnsNameValidTLD.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_dnsname_not_valid_tld",
            filename = "dnsNameNotValidTLD.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_dnsname_not_valid_tld",
            filename = "dnsNameNotYetValidTLD.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

    @LintTest(
            name = "e_dnsname_not_valid_tld",
            filename = "dnsNameNoLongerValidTLD.pem",
            expectedResultStatus = Status.ERROR)
    void testCase04() {
    }

    @LintTest(
            name = "e_dnsname_not_valid_tld",
            filename = "dnsNameWasValidTLD.pem",
            expectedResultStatus = Status.PASS)
    void testCase05() {
    }

    @LintTest(
            name = "e_dnsname_not_valid_tld",
            filename = "dnsNameOnionTLD.pem",
            expectedResultStatus = Status.PASS)
    void testCase06() {
    }

    @Disabled("The certificate has only IPs. Should return NA.")
    @LintTest(
            name = "e_dnsname_not_valid_tld",
            filename = "dnsNameWithIPInCN.pem",
            expectedResultStatus = Status.PASS)
    void testCase07() {
    }

}