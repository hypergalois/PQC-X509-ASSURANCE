package de.mtg.jzlint.lints.etsi;

import java.security.cert.X509Certificate;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_qcstatem_qcsscd_valid",
        description = "Checks that a QC Statement of the type id-etsi-qcs-QcSSCD has the correct form",
        citation = "ETSI EN 319 412 - 5 V2.2.1 (2017 - 11) / Section 4.2.2",
        source = Source.ETSI_ESI,
        effectiveDate = EffectiveDate.EtsiEn319_412_5_V2_2_1_Date)
public class QcstatemQcsscdValid implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        ASN1OctetString qCStatementsValue = ASN1OctetString.getInstance(certificate.getExtensionValue(QcUtils.QC_OID.getId()));
        ASN1Sequence qCStatements = ASN1Sequence.getInstance(qCStatementsValue.getOctets());

        Iterator<ASN1Encodable> iterator = qCStatements.iterator();

        while (iterator.hasNext()) {
            ASN1Sequence qcStatement = (ASN1Sequence) iterator.next();
            ASN1ObjectIdentifier statementId = (ASN1ObjectIdentifier) qcStatement.getObjectAt(0);

            if (statementId.equals(QcUtils.id_etsi_qcs_QcSSCD) && qcStatement.size() != 1) {
                return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcSSCD value");
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return QcUtils.isEtsiQcStatementPresent(certificate, QcUtils.id_etsi_qcs_QcSSCD);
    }

}
