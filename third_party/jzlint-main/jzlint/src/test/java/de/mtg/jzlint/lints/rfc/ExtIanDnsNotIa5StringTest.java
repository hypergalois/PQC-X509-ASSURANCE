package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtIanDnsNotIa5StringTest {

    @LintTest(
            name = "e_ext_ian_dns_not_ia5_string",
            filename = "IANDNSIA5String.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_ian_dns_not_ia5_string",
            filename = "IANDNSNotIA5String.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

}