package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DnsnameBadCharacterInLabelTest {

    @LintTest(
            name = "e_dnsname_bad_character_in_label",
            filename = "dnsNameBadCharacterInLabel.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_dnsname_bad_character_in_label",
            filename = "dnsNameClientCert.pem",
            expectedResultStatus = Status.NA)
    void testCase02() {
    }

    @LintTest(
            name = "e_dnsname_bad_character_in_label",
            filename = "validComodo.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

}