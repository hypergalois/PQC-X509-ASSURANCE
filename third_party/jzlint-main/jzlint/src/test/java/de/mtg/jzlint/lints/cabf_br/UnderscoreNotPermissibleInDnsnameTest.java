package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class UnderscoreNotPermissibleInDnsnameTest {

    @LintTest(
            name = "e_underscore_not_permissible_in_dnsname",
            filename = "dNSNameNoUnderscoresHardEnforcementPeriod.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "No underscores")
    void testCase01() {
    }

    @LintTest(
            name = "e_underscore_not_permissible_in_dnsname",
            filename = "dNSNameWithUnderscoresHardEnforcementPeriod.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "An underscore")
    void testCase02() {
    }

    @LintTest(
            name = "e_underscore_not_permissible_in_dnsname",
            filename = "dNSNoUnderscoresBeforeHardEnforcementPeriod.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "Not effective")
    void testCase03() {
    }

}
