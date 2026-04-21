package de.mtg.jzlint.lints.etsi;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class QcstatemMandatoryEtsiStatemsTest {

    @LintTest(
            name = "e_qcstatem_mandatory_etsi_statems",
            filename = "QcStmtEtsiMissingMandatoryCert14.pem",
            expectedResultStatus = Status.ERROR)
    void testCase01() {
    }

    @LintTest(
            name = "e_qcstatem_mandatory_etsi_statems",
            filename = "QcStmtEtsiMissingPDSCert16.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_qcstatem_mandatory_etsi_statems",
            filename = "QcStmtEtsiValidCert03.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

    @LintTest(
            name = "e_qcstatem_mandatory_etsi_statems",
            filename = "QcStmtEtsiEsealValidCert02.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

    @LintTest(
            name = "e_qcstatem_mandatory_etsi_statems",
            filename = "QcStmtEtsiTwoQcTypesCert15.pem",
            expectedResultStatus = Status.PASS)
    void testCase05() {
    }

    @LintTest(
            name = "e_qcstatem_mandatory_etsi_statems",
            filename = "QcStmtEtsiValidCert11.pem",
            expectedResultStatus = Status.PASS)
    void testCase06() {
    }

    @LintTest(
            name = "e_qcstatem_mandatory_etsi_statems",
            filename = "QcStmtEtsiNoQcStatmentsCert22.pem",
            expectedResultStatus = Status.NA)
    void testCase07() {
    }

}