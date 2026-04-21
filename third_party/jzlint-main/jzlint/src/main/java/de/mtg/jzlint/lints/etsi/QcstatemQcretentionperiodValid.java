package de.mtg.jzlint.lints.etsi;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_qcstatem_qcretentionperiod_valid",
        description = "Checks that a QC Statement of the type id-etsi-qcs-QcRetentionPeriod has the correct form",
        citation= "ETSI EN 319 412 - 5 V2.2.1 (2017 - 11)/ Section 4.3.3",
        source = Source.ETSI_ESI,
        effectiveDate = EffectiveDate.EtsiEn319_412_5_V2_2_1_Date)
public class QcstatemQcretentionperiodValid implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        ASN1Encodable statementInfo = QcUtils.getStatementInfo(certificate, QcUtils.id_etsi_qcs_QcRetentionPeriod);

        if (!(statementInfo instanceof ASN1Integer)) {
            return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcRetentionPeriod value");
        }

        if (((ASN1Integer) statementInfo).getValue().compareTo(BigInteger.ZERO) == -1) {
            return LintResult.of(Status.ERROR, "retention period is negative");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return QcUtils.isEtsiQcStatementPresent(certificate, QcUtils.id_etsi_qcs_QcRetentionPeriod);
    }

}
