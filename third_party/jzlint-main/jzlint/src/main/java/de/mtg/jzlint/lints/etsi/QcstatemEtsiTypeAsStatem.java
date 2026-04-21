package de.mtg.jzlint.lints.etsi;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_qcstatem_etsi_type_as_statem",
        description = "Checks for erroneous QC Statement OID that actually are represented by ETSI ESI QC type OID.",
        citation = "ETSI EN 319 412 - 5 V2.2.1 (2017 - 11) / Section 4.2.3",
        source = Source.ETSI_ESI,
        effectiveDate = EffectiveDate.EtsiEn319_412_5_V2_2_1_Date)
public class QcstatemEtsiTypeAsStatem implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final List<ASN1ObjectIdentifier> allQcTypeOIDs = Arrays.asList(QcUtils.id_etsi_qcs_esign,
                QcUtils.id_etsi_qcs_eseal,
                QcUtils.id_etsi_qcs_web);

        StringBuilder stringBuilder = new StringBuilder();
        for (ASN1ObjectIdentifier statementId : allQcTypeOIDs) {
            if (QcUtils.getAllStatementIds(certificate).contains(statementId)) {
                stringBuilder.append(String.format("ETSI QC Type OID %s used as QC statement", statementId.getId()));
                stringBuilder.append(";");
            }
        }

        if (!stringBuilder.toString().isEmpty()) {
            return LintResult.of(Status.ERROR, stringBuilder.toString());
        }

        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return QcUtils.hasQcStatementsExtension(certificate);
    }

}
