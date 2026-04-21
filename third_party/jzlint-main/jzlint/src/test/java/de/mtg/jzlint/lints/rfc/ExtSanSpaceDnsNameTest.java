package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class ExtSanSpaceDnsNameTest {

    @LintTest(
            name = "e_ext_san_space_dns_name",
            filename = "orgValGoodAllFields.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_ext_san_space_dns_name",
            filename = "SANWithSpaceDNS.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }
}