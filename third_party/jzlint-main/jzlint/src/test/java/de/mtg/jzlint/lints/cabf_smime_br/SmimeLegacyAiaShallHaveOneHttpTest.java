package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SmimeLegacyAiaShallHaveOneHttpTest {

    @LintTest(
            name = "e_smime_legacy_aia_shall_have_one_http",
            filename = "smime/legacyAiaOneHTTPOneLdap.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - aia with one ldap URI and one HTTP in each method")
    void testCase01() {
    }

    @LintTest(
            name = "e_smime_legacy_aia_shall_have_one_http",
            filename = "smime/legacyAiaLdapOnly.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "error - aia with only ldap URIs HTTP in each method")
    void testCase02() {
    }

}