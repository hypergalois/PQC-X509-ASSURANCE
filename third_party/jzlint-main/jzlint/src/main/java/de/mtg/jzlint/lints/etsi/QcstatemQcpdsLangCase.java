package de.mtg.jzlint.lints.etsi;

import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "w_qcstatem_qcpds_lang_case",
        description = "Checks that a QC Statement of the type id-etsi-qcs-QcPDS features a language code comprised of only lower case letters",
        citation = "ETSI EN 319 412 - 5 V2.2.1 (2017 - 11) / Section 4.3.4",
        source = Source.ETSI_ESI,
        effectiveDate = EffectiveDate.EtsiEn319_412_5_V2_2_1_Date)
public class QcstatemQcpdsLangCase implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        ASN1Encodable statementInfo = QcUtils.getStatementInfo(certificate, QcUtils.id_etsi_qcs_QcPDS);

        if (!(statementInfo instanceof ASN1Sequence)) {
            return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcEuPDS value");
        }

        StringBuilder stringBuilder = new StringBuilder();

        ASN1Sequence qcEuPDS = (ASN1Sequence) statementInfo;

        Iterator<ASN1Encodable> iterator = qcEuPDS.iterator();
        while (iterator.hasNext()) {
            ASN1Encodable pdsLocation = iterator.next();

            if (!(pdsLocation instanceof ASN1Sequence)) {
                return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcEuPDS value");
            }

            ASN1Encodable language = ((ASN1Sequence) pdsLocation).getObjectAt(1);

            if (language instanceof ASN1PrintableString) {

                ASN1PrintableString languageValue = (ASN1PrintableString) language;

                Pattern pattern = Pattern.compile("[a-z]*");
                Matcher matcher = pattern.matcher(languageValue.getString());
                if (!matcher.matches()) {
                    stringBuilder.append(String.format("PDS location has a language code %s containing invalid letters", languageValue.getString()));
                    stringBuilder.append(";");
                }
            } else {
                return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcEuPDS value");
            }
        }

        if (!stringBuilder.toString().isEmpty()) {
            return LintResult.of(Status.WARN, stringBuilder.toString());
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return QcUtils.isEtsiQcStatementPresent(certificate, QcUtils.id_etsi_qcs_QcPDS);
    }

}
