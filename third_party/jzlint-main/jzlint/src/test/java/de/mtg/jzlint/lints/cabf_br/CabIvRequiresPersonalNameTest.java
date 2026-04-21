package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class CabIvRequiresPersonalNameTest {

    @LintTest(
            name = "e_cab_iv_requires_personal_name",
            filename = "indivValGoodAllFields.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_cab_iv_requires_personal_name",
            filename = "indivValSurnameOnly.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_cab_iv_requires_personal_name",
            filename = "indivValGivenNameOnly.pem",
            expectedResultStatus = Status.ERROR)
    void testCase03() {
    }

    @LintTest(
            name = "e_cab_iv_requires_personal_name",
            filename = "indivValNoOrgOrPersonalNames.pem",
            expectedResultStatus = Status.ERROR)
    void testCase04() {
    }
}