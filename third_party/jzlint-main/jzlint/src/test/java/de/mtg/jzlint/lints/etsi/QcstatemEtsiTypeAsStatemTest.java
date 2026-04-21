package de.mtg.jzlint.lints.etsi;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class QcstatemEtsiTypeAsStatemTest {

    @LintTest(
            name = "e_qcstatem_etsi_type_as_statem",
            filename = "QcStmtEtsiQcTypeAsQcStmtCert10.pem",
            expectedResultStatus = Status.ERROR,
            expectedResultDetails = "ETSI QC Statement is present and QC Statements extension is marked critical")
    void testCase01() {
    }

    @LintTest(
            name = "e_qcstatem_etsi_type_as_statem",
            filename = "QcStmtEtsiValidCert03.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_qcstatem_etsi_type_as_statem",
            filename = "QcStmtEtsiEsealValidCert02.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

    @LintTest(
            name = "e_qcstatem_etsi_type_as_statem",
            filename = "QcStmtEtsiTwoQcTypesCert15.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

    @LintTest(
            name = "e_qcstatem_etsi_type_as_statem",
            filename = "QcStmtEtsiNoQcStatmentsCert22.pem",
            expectedResultStatus = Status.NA)
    void testCase05() {
    }

    @LintTest(
            name = "e_qcstatem_etsi_type_as_statem",
            filename = "QcStmtEtsiValidCert24.pem",
            expectedResultStatus = Status.PASS)
    void testCase06() {
    }

}