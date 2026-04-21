package de.mtg.jzlint.lints.cabf_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class OrganizationalUnitNameProhibitedTest {

    @LintTest(
            name = "e_organizational_unit_name_prohibited",
            filename = "ouAbsentAfterSep22.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Certificate issued after rule that doesn't have an OU")
    void testCase01() {
    }

    @LintTest(
            name = "e_organizational_unit_name_prohibited",
            filename = "ouPresentBeforeSep22.pem",
            expectedResultStatus = Status.NE,
            certificateDescription = "Certificate issued before rule comes into effect")
    void testCase02() {
    }

    @LintTest(
            name = "e_organizational_unit_name_prohibited",
            filename = "ouPresentCATrueAfterSep22.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "CA Certificate issued after rule comes into effect")
    void testCase03() {
    }

    @LintTest(
            name = "e_organizational_unit_name_prohibited",
            filename = "ouPresentAfterSep22.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Certificate issued after rule applies that contains an OU")
    void testCase04() {
    }

}