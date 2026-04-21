package de.mtg.jzlint.lints.etsi;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class QcstatemEtsiPresentQcsCriticalTest {

    @LintTest(
            name = "e_qcstatem_etsi_present_qcs_critical",
            filename = "QcStmtEtsiWrongCriticalityCert06.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_qcstatem_etsi_present_qcs_critical",
            filename = "QcStmtEtsiValidCert03.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_qcstatem_etsi_present_qcs_critical",
            filename = "QcStmtEtsiNoQcStatmentsCert22.pem",
            expectedResultStatus = Status.NA)
    void testCase03() {
    }

}