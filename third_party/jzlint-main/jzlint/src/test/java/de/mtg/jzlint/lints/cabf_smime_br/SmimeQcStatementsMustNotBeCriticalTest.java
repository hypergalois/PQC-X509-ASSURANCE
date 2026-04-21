package de.mtg.jzlint.lints.cabf_smime_br;

import org.junit.jupiter.api.extension.ExtendWith;

import de.mtg.jzlint.LintTest;
import de.mtg.jzlint.LintTestExtension;
import de.mtg.jzlint.Status;

@ExtendWith(LintTestExtension.class)
class SmimeQcStatementsMustNotBeCriticalTest {

    @LintTest(
            name = "e_smime_qc_statements_must_not_be_critical",
            filename = "smime/legacyAiaOneHTTPOneLdap.pem",
            expectedResultStatus = Status.NA,
            certificateDescription = "N/A - no qcStatements extension")
    void testCase01() {
    }

    @LintTest(
            name = "e_smime_qc_statements_must_not_be_critical",
            filename = "smime/e_smime_qc_statements_must_not_be_critical_pass.pem",
            expectedResultStatus = Status.PASS,
            certificateDescription = "Pass - qcStatements not critical")
    void testCase02() {
    }

    @LintTest(
            name = "e_smime_qc_statements_must_not_be_critical",
            filename = "smime/e_smime_qc_statements_must_not_be_critical_fail.pem",
            expectedResultStatus = Status.ERROR,
            certificateDescription = "Fail - qcStatements critical")
    void testCase03() {
    }

}