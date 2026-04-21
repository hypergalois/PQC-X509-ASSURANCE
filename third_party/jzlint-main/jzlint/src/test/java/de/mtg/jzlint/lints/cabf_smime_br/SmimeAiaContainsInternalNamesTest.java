package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SmimeAiaContainsInternalNamesTest {

    @LintTest(
            name = "w_smime_aia_contains_internal_names",
            filename = "smime/aiaWithValidNamesStrict.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - aia with valid names")
    void testCase01() {
    }

    @LintTest(
            name = "w_smime_aia_contains_internal_names",
            filename = "smime/aiaWithInternalNamesStrict.pem",
            expectedResultStatus = Status.WARN,
            certificateDescription = "warn - aia with internal names in AIA OCSP ")
    void testCase02() {
    }

    @LintTest(
            name = "w_smime_aia_contains_internal_names",
            filename = "smime/aiaWithInternalNamesCaIssuersStrict.pem",
            expectedResultStatus = Status.WARN,
            certificateDescription = "warn - aia with internal names in AIA CA issuers ")
    void testCase03() {
    }

    @LintTest(
            name = "w_smime_aia_contains_internal_names",
            filename = "smime/aiaWithLDAPOCSPStrict.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "warn - aia with valid names, one is ldap")
    void testCase04() {
    }

    @LintTest(
            name = "w_smime_aia_contains_internal_names",
            filename = "smime/aiaWithIPAddress.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "pass - aia with IP address in host part of the URL")
    void testCase05() {
    }

}