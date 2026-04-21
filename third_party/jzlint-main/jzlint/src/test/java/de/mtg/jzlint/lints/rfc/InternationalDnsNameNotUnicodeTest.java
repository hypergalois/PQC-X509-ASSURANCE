package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class InternationalDnsNameNotUnicodeTest {

    @LintTest(
            name = "e_international_dns_name_not_unicode",
            filename = "idnMalformedUnicode.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_international_dns_name_not_unicode",
            filename = "idnCorrectUnicode.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}