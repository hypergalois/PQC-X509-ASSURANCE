package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CaOrganizationNameMissingTest {

    @LintTest(
            name = "e_ca_organization_name_missing",
            filename = "caOrgNameEmpty.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_ca_organization_name_missing",
            filename = "caOrgNameMissing.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_ca_organization_name_missing",
            filename = "caValOrgName.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }
}