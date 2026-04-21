package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SmimeStrictAiaShallHaveHttpOnlyTest {

    @LintTest(
            name = "e_smime_strict_aia_shall_have_http_only",
            filename = "smime/aiaWithValidNamesStrict.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - aia with valid names")
    void testCase01() {
    }

    @LintTest(
            name = "e_smime_strict_aia_shall_have_http_only",
            filename = "smime/aiaWithInternalNamesStrict.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "warn - aia with internal names")
    void testCase02() {
    }

    @LintTest(
            name = "e_smime_strict_aia_shall_have_http_only",
            filename = "smime/aiaWithLDAPOCSPStrict.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "warn - aia with internal names")
    void testCase03() {
    }

}