package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SubjectContainsOrganizationalUnitNameAndNoOrganizationNameTest {

    @LintTest(
            name = "e_subject_contains_organizational_unit_name_and_no_organization_name",
            filename = "subjectDnWithoutOuEntry.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "Subject does not contain organizational unit name")
    void testCase01() {
    }

    @LintTest(
            name = "e_subject_contains_organizational_unit_name_and_no_organization_name",
            filename = "subjectDnWithOuEntryButWithoutOEntry.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "subject:organizationalUnitName is prohibited if subject:organizationName is absent")
    void testCase02() {
    }

    @LintTest(
            name = "e_subject_contains_organizational_unit_name_and_no_organization_name",
            filename = "subjectWithOandOUBeforeEffectiveDate.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "Subject contains organizational unit and organization name but is issued before the effective date")
    void testCase03() {
    }

    @LintTest(
            name = "e_subject_contains_organizational_unit_name_and_no_organization_name",
            filename = "subjectWithOandOUAfterEffectiveDate.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Subject contains organizational unit and organization name and is issued after the effective date")
    void testCase04() {
    }

}
