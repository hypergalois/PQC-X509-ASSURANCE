package de.mtg.jzlint.lints.rfc;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;


@ExtendWith(LintTestExtension.class)
class PathLenConstraintZeroOrLessTest {

    @LintTest(
            name = "e_path_len_constraint_zero_or_less",
            filename = "caMaxPathNegative.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_path_len_constraint_zero_or_less",
            filename = "subCertPathLenNegative.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }

    @LintTest(
            name = "e_path_len_constraint_zero_or_less",
            filename = "caMaxPathLenPositive.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }
}