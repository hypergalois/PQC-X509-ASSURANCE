package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class DistributionPointMissingLdapOrUriTest {
    @LintTest(
            name = "w_distribution_point_missing_ldap_or_uri",
            filename = "crlDistribNoHTTP.pem",
            expectedResultStatus = Status.WARN)
    void testCase01() {
    }

    @LintTest(
            name = "w_distribution_point_missing_ldap_or_uri",
            filename = "crlDistribWithHTTP.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "w_distribution_point_missing_ldap_or_uri",
            filename = "crlDistribWithLDAP.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }
}
