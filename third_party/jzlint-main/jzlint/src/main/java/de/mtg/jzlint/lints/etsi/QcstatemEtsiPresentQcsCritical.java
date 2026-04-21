package de.mtg.jzlint.lints.etsi;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_qcstatem_etsi_present_qcs_critical",
        description = "Checks that a QC Statement which contains any of the id-etsi-qcs-... QC Statements is not marked critical",
        citation = "ETSI EN 319 412 - 5 V2.2.1 (2017 - 11) / Section 4.1",
        source = Source.ETSI_ESI,
        effectiveDate = EffectiveDate.EtsiEn319_412_5_V2_2_1_Date)
public class QcstatemEtsiPresentQcsCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (QcUtils.isQcStatementsExtensionCritical(certificate)) {
            return LintResult.of(Status.ERROR, "ETSI QC Statement is present and QC Statements extension is marked critical");
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return QcUtils.isAnyEtsiQcStatementPresent(certificate);
    }

}
