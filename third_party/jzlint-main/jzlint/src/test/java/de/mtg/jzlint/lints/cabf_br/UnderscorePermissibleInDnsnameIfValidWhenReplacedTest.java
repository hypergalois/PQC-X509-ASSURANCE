package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class UnderscorePermissibleInDnsnameIfValidWhenReplacedTest {

    @LintTest(
            name = "e_underscore_permissible_in_dnsname_if_valid_when_replaced",
            filename = "dNSNameUnderscoreValidWhenReplaced.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Valid when replaced")
    void testCase01() {
    }

    @LintTest(
            name = "e_underscore_permissible_in_dnsname_if_valid_when_replaced",
            filename = "dNSNameUnderscoreNotValidWhenReplaced.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Invalid when replaced")
    void testCase02() {
    }

    @LintTest(
            name = "e_underscore_permissible_in_dnsname_if_valid_when_replaced",
            filename = "dNSUnderscoresPermissibleOutOfDateRange.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "Not effective")
    void testCase03() {
    }

}
