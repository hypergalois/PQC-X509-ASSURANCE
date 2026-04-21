package de.mtg.jzlint.lints.etsi;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_qcstatem_mandatory_etsi_statems",
        description = "Checks that a QC Statement that contains at least one of the ETSI ESI statements, also features the set of mandatory ETSI ESI QC statements.",
        citation = "ETSI EN 319 412 - 5 V2.2.1 (2017 - 11) / Section 5",
        source = Source.ETSI_ESI,
        effectiveDate = EffectiveDate.EtsiEn319_412_5_V2_2_1_Date)
public class QcstatemMandatoryEtsiStatems implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (!QcUtils.isEtsiQcStatementPresent(certificate, QcUtils.id_etsi_qcs_QcCompliance)) {
            return LintResult.of(Status.ERROR, "missing mandatory ETSI QC statement");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return QcUtils.isAnyEtsiQcStatementPresent(certificate);
    }

}
