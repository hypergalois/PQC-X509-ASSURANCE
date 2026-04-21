package de.mtg.jzlint.lints.etsi;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;


@ExtendWith(LintTestExtension.class)
class QcstatemQccomplianceValidTest {

    @LintTest(
            name = "e_qcstatem_qccompliance_valid",
            filename = "QcStmtEtsiValidCert03.pem",
            expectedResultStatus = Status.PASS)
    void testCase01() {
    }

    @LintTest(
            name = "e_qcstatem_qccompliance_valid",
            filename = "QcStmtEtsiEsealValidCert02.pem",
            expectedResultStatus = Status.PASS)
    void testCase02() {
    }

    @LintTest(
            name = "e_qcstatem_qccompliance_valid",
            filename = "QcStmtEtsiTwoQcTypesCert15.pem",
            expectedResultStatus = Status.PASS)
    void testCase03() {
    }

    @LintTest(
            name = "e_qcstatem_qccompliance_valid",
            filename = "QcStmtEtsiValidCert11.pem",
            expectedResultStatus = Status.PASS)
    void testCase04() {
    }

    @LintTest(
            name = "e_qcstatem_qccompliance_valid",
            filename = "QcStmtEtsiMissingMandatoryCert14.pem",
            expectedResultStatus = Status.NA)
    void testCase05() {
    }

    @LintTest(
            name = "e_qcstatem_qccompliance_valid",
            filename = "QcStmtEtsiNoQcStatmentsCert22.pem",
            expectedResultStatus = Status.NA)
    void testCase06() {
    }


}