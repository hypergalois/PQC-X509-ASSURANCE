package de.mtg.jzlint.lints.etsi;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;


/*
esi4-qcStatement-2 QC-STATEMENT ::= { SYNTAX QcEuLimitValue IDENTIFIED
BY id-etsi-qcs-QcLimitValue }

QcEuLimitValue ::= MonetaryValue

MonetaryValue::= SEQUENCE {
    currency Iso4217CurrencyCode,
    amount INTEGER,
    exponent INTEGER
}

-- value = amount * 10^exponent
Iso4217CurrencyCode ::= CHOICE {
    alphabetic PrintableString (SIZE (3)), -- Recommended
    numeric INTEGER (1..999)
}

-- Alphabetic or numeric currency code as defined in ISO 4217
-- It is recommended that the Alphabetic form is used

 */

@Lint(
        name = "e_qcstatem_qclimitvalue_valid",
        description = "Checks that a QC Statement of the type id-etsi-qcs-QcLimitValue has the correct form",
        citation = "ETSI EN 319 412 - 5 V2.2.1 (2017 - 11) / Section 4.3.2",
        source = Source.ETSI_ESI,
        effectiveDate = EffectiveDate.EtsiEn319_412_5_V2_2_1_Date)
public class QcstatemQclimitvalueValid implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        ASN1Encodable statementInfo = QcUtils.getStatementInfo(certificate, QcUtils.id_etsi_qcs_QcLimitValue);

        if (!(statementInfo instanceof ASN1Sequence)) {
            return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcLimitValue");
        }

        StringBuilder stringBuilder = new StringBuilder();

        ASN1Sequence qcEuLimitValue = (ASN1Sequence) statementInfo;
        ASN1Encodable currency = qcEuLimitValue.getObjectAt(0);

        if (currency instanceof ASN1PrintableString) {

            ASN1PrintableString currencyValue = (ASN1PrintableString) currency;

            if (currencyValue.getString().length() != 3) {
                stringBuilder.append("invalid string length of currency code");
                stringBuilder.append(";");
            }

            Pattern pattern = Pattern.compile("[a-zA-Z]*");
            Matcher matcher = pattern.matcher(currencyValue.getString());
            if (!matcher.matches()) {
                stringBuilder.append("currency code string contains not only letters");
                stringBuilder.append(";");
            }

        } else if (currency instanceof ASN1Integer) {

            ASN1Integer currencyValue = (ASN1Integer) currency;

            if (currencyValue.getValue().compareTo(BigInteger.ONE) == -1 || currencyValue.getValue().compareTo(BigInteger.valueOf(999)) == 1) {
                stringBuilder.append("numeric currency code is out of range");
                stringBuilder.append(";");
            }
        } else {
            stringBuilder.append("parsed QcStatem is not an EtsiQcLimitValue");
            stringBuilder.append(";");
        }

        ASN1Encodable amount = qcEuLimitValue.getObjectAt(1);

        if (amount instanceof ASN1Integer) {
            ASN1Integer amountValue = (ASN1Integer) amount;
            if (amountValue.getValue().compareTo(BigInteger.ZERO) == -1) {
                stringBuilder.append("amount is negative");
                stringBuilder.append(";");
            }
        } else {
            return LintResult.of(Status.ERROR, "parsed QcStatem is not an EtsiQcLimitValue");
        }

        if (!stringBuilder.toString().isEmpty()) {
            return LintResult.of(Status.ERROR, stringBuilder.toString());
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return QcUtils.isEtsiQcStatementPresent(certificate, QcUtils.id_etsi_qcs_QcLimitValue);
    }

}
