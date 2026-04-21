package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanDnsNameTooLongTest {

    @LintTest(
            name = "e_ext_san_dns_name_too_long",
            filename = "orgValGoodAllFields.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_dns_name_too_long",
            filename = "SANDNSTooLong.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }
}