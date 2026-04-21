package de.mtg.jzlint.lints.community;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class IanDnsNameIncludesNullCharTest {

    @LintTest(
            name = "e_ian_dns_name_includes_null_char",
            filename = "IANDNSNull.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ian_dns_name_includes_null_char",
            filename = "IANURIValid.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

}