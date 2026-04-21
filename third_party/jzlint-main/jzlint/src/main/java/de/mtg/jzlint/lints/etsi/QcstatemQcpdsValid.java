package de.mtg.jzlint.lints.etsi;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_qcstatem_qcpds_valid",
        description = "Checks that a QC Statement of the type id-etsi-qcs-QcPDS has the correct form",
        citation = "ETSI EN 319 412 - 5 V2.2.1 (2017 - 11) / Section 4.3.4",
        source = Source.ETSI_ESI,
        effectiveDate = EffectiveDate.EtsiEn319_412_5_V2_2_1_Date)
public class QcstatemQcpdsValid implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        ASN1Encodable statementInfo = QcUtils.getStatementInfo(certificate, QcUtils.id_etsi_qcs_QcPDS);

        if (!(statementInfo instanceof ASN1Sequence)) {
            return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcEuPDS value");
        }

        StringBuilder stringBuilder = new StringBuilder();

        ASN1Sequence qcEuPDS = (ASN1Sequence) statementInfo;

        if (qcEuPDS.size() < 1) {
            stringBuilder.append("PDS list is empty");
            stringBuilder.append(";");
        }

        Iterator<ASN1Encodable> iterator = qcEuPDS.iterator();

        List<String> languageCodes = new ArrayList<>();

        boolean foundEn = false;
        while (iterator.hasNext()) {
            ASN1Encodable pdsLocation = iterator.next();

            if (!(pdsLocation instanceof ASN1Sequence)) {
                return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcEuPDS value");
            }

            ASN1Sequence pdsLocationSequence = (ASN1Sequence) pdsLocation;

            if (pdsLocationSequence.size() != 2) {
                stringBuilder.append(String.format("PDS location %d has a language code with an invalid length", pdsLocationSequence.size()));
                stringBuilder.append(";");
            }


            ASN1Encodable url = pdsLocationSequence.getObjectAt(0);

            if (!(url instanceof ASN1IA5String)) {
                return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcEuPDS value. Wrong url encoding.");
            }

            ASN1Encodable language = pdsLocationSequence.getObjectAt(1);

            if (language instanceof ASN1PrintableString) {

                ASN1PrintableString languageValue = (ASN1PrintableString) language;
                String stringValue = languageValue.getString();

                if (stringValue.length() != 2) {
                    stringBuilder.append(String.format("PDS location %s has a language code with an invalid length", stringValue));
                    stringBuilder.append(";");
                }

                if (stringValue.equalsIgnoreCase("en")) {
                    foundEn = true;
                }

                if (languageCodes.contains(stringValue)) {
                    stringBuilder.append(String.format("country code %s appears multiple times", stringValue));
                    stringBuilder.append(";");
                } else {
                    languageCodes.add(stringValue);
                }
            } else {
                return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcEuPDS value");
            }
        }

        if (!foundEn) {
            stringBuilder.append("no english PDS present");
            stringBuilder.append(";");
        }

        if (!stringBuilder.toString().isEmpty()) {
            return LintResult.of(Status.ERROR, stringBuilder.toString());
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return QcUtils.isEtsiQcStatementPresent(certificate, QcUtils.id_etsi_qcs_QcPDS);
    }

}
