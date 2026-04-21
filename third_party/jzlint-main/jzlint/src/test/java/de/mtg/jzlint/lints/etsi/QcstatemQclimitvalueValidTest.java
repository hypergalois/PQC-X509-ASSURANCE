package de.mtg.jzlint.lints.etsi;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class QcstatemQclimitvalueValidTest {


    @LintTest(
            name = "e_qcstatem_qclimitvalue_valid",
            filename = "QcStmtValidLimitValue.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_qcstatem_qclimitvalue_valid",
            filename = "QcStmtInvalidLimitValue.pem",
            expectedResultStatus = Status.ERROR)
    void testCase02() {
    }
}