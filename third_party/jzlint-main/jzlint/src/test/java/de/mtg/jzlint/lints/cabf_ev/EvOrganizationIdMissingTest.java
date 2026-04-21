package de.mtg.jzlint.lints.cabf_ev;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class EvOrganizationIdMissingTest {

    @LintTest(
            name = "e_ev_organization_id_missing",
            filename = "evOrgIdExtMissing_NoOrgId.pem",
            expectedResultStatus = Status.NA)
    void testCase01() {
    }

    @LintTest(
            name = "e_ev_organization_id_missing",
            filename = "evOrgIdExtMissing_CABFOrgIdExtMissingButBeforeEffectiveDate.pem",
            expectedResultStatus = Status.NE)
    void testCase02() {
    }

    @LintTest(
            name = "e_ev_organization_id_missing",
            filename = "evOrgIdExtMissing_ValidButBeforeEffectiveDate.pem",
            expectedResultStatus = Status.NE)
    void testCase03() {
    }

    @LintTest(
            name = "e_ev_organization_id_missing",
            filename = "evOrgIdExtMissing_Invalid.pem",
            expectedResultStatus = Status.ERROR)
    void testCase04() {
    }

    @LintTest(
            name = "e_ev_organization_id_missing",
            filename = "evOrgIdExtMissing_Valid.pem",
            expectedResultStatus = Status.PASS)
    void testCase05() {
    }


}