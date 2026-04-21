package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtIanSpaceDnsNameTest {

    @LintTest(
            name = "e_ext_ian_space_dns_name",
            filename = "IANEmptyDNS.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_ian_space_dns_name",
            filename = "IANNonEmptyDNS.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}