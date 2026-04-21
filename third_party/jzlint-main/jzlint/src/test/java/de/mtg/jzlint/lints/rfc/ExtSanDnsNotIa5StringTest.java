package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanDnsNotIa5StringTest {

    @LintTest(
            name = "e_ext_san_dns_not_ia5_string",
            filename = "SANDNSNotIA5String.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_dns_not_ia5_string",
            filename = "SANCaGood.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }
}
