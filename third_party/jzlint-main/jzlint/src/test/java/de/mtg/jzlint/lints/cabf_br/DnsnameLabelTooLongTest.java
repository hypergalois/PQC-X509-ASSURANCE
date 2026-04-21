package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DnsnameLabelTooLongTest {

    @LintTest(
            name = "e_dnsname_label_too_long",
            filename = "dnsNameLabelTooLong.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

}