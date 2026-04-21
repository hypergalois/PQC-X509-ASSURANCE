package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CabDvConflictsWithOrgTest {

    @LintTest(
            name = "e_cab_dv_conflicts_with_org",
            filename = "domainValGoodSubject.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_cab_dv_conflicts_with_org",
            filename = "domainValWithOrg.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }
}