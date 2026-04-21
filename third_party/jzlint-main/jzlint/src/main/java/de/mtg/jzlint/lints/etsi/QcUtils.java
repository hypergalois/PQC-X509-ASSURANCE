package de.mtg.jzlint.lints.etsi;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

import de.mtg.jzlint.utils.Utils;

public class QcUtils {

    public static final ASN1ObjectIdentifier id_etsi_qcs = new ASN1ObjectIdentifier("0.4.0.1862.1");
    public static final ASN1ObjectIdentifier id_etsi_qcs_QcCompliance = id_etsi_qcs.branch("1");
    public static final ASN1ObjectIdentifier id_etsi_qcs_QcLimitValue = id_etsi_qcs.branch("2");
    public static final ASN1ObjectIdentifier id_etsi_qcs_QcRetentionPeriod = id_etsi_qcs.branch("3");
    public static final ASN1ObjectIdentifier id_etsi_qcs_QcSSCD = id_etsi_qcs.branch("4");
    public static final ASN1ObjectIdentifier id_etsi_qcs_QcPDS = id_etsi_qcs.branch("5");
    public static final ASN1ObjectIdentifier id_etsi_qcs_QcType = id_etsi_qcs.branch("6");
    public static final ASN1ObjectIdentifier id_etsi_qcs_esign = id_etsi_qcs_QcType.branch("1");
    public static final ASN1ObjectIdentifier id_etsi_qcs_eseal = id_etsi_qcs_QcType.branch("2");
    public static final ASN1ObjectIdentifier id_etsi_qcs_web = id_etsi_qcs_QcType.branch("3");
    private static final List<ASN1ObjectIdentifier> allEtsiQcStatements = Arrays.asList(id_etsi_qcs_QcCompliance,
            id_etsi_qcs_QcLimitValue,
            id_etsi_qcs_QcRetentionPeriod,
            id_etsi_qcs_QcSSCD,
            id_etsi_qcs_QcPDS,
            id_etsi_qcs_QcType);

    public static final ASN1ObjectIdentifier QC_OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3");


    public static boolean hasQcStatementsExtension(X509Certificate certificate) {
        return Utils.hasExtension(certificate, QC_OID.getId());
    }

    public static boolean isQcStatementsExtensionCritical(X509Certificate certificate) {
        return Utils.isExtensionCritical(certificate, QC_OID.getId());
    }

    public static boolean isAnyEtsiQcStatementPresent(X509Certificate certificate) {
        if (!hasQcStatementsExtension(certificate)) {
            return false;
        }

        return allEtsiQcStatements.stream().anyMatch(statementId -> getAllStatementIds(certificate).contains(statementId));
    }

    public static boolean isEtsiQcStatementPresent(X509Certificate certificate, ASN1ObjectIdentifier etsiQcStatementOID) {
        if (!hasQcStatementsExtension(certificate)) {
            return false;
        }
        return getAllStatementIds(certificate).contains(etsiQcStatementOID);
    }


    public static List<ASN1ObjectIdentifier> getAllStatementIds(X509Certificate certificate) {
        List<ASN1ObjectIdentifier> allStatementIds = new ArrayList<>();
        if (!hasQcStatementsExtension(certificate)) {
            return allStatementIds;
        }

        ASN1OctetString qCStatementsValue = ASN1OctetString.getInstance(certificate.getExtensionValue(QC_OID.getId()));
        ASN1Sequence qCStatements = ASN1Sequence.getInstance(qCStatementsValue.getOctets());

        Iterator<ASN1Encodable> iterator = qCStatements.iterator();

        while (iterator.hasNext()) {
            ASN1Sequence qcStatement = (ASN1Sequence) iterator.next();
            ASN1ObjectIdentifier statementId = (ASN1ObjectIdentifier) qcStatement.getObjectAt(0);
            allStatementIds.add(statementId);
        }
        return allStatementIds;
    }


    public static ASN1Encodable getStatementInfo(X509Certificate certificate, ASN1ObjectIdentifier qcStatementOID) {
        if (!hasQcStatementsExtension(certificate)) {
            return null;
        }

        ASN1OctetString qCStatementsValue = ASN1OctetString.getInstance(certificate.getExtensionValue(QC_OID.getId()));
        ASN1Sequence qCStatements = ASN1Sequence.getInstance(qCStatementsValue.getOctets());

        Iterator<ASN1Encodable> iterator = qCStatements.iterator();

        while (iterator.hasNext()) {
            ASN1Sequence qcStatement = (ASN1Sequence) iterator.next();
            ASN1ObjectIdentifier statementId = (ASN1ObjectIdentifier) qcStatement.getObjectAt(0);

            if (statementId.equals(qcStatementOID) && qcStatement.size() > 1) {
                return qcStatement.getObjectAt(1);
            }

        }
        return null;
    }


}
