package de.mtg.jlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.style.BCStyle;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 RFC 5280: A.1
 --  specifications of Upper Bounds MUST be regarded as mandatory
 --  from Annex B of ITU-T X.411 Reference Definition of MTS Parameter
 --  Upper Bounds
 ************************************************/

@Lint(
        name = "w_issuer_surname_recommended_max_length",
        description = "X.411 (1988) describes ub-common-name-length to be 64 bytes long. As systems may have targeted this length, for compatibility purposes it may be prudent to limit surnames to this length.",
        citation = "ITU-T Rec. X.411 (11/1988), Annex B Reference Definition of MTS Parameter Upper Bounds",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class IssuerSurnameRecommendedMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> issuerNameComponent = Utils.getIssuerDNNameComponent(certificate, BCStyle.SURNAME.getId());

        for (AttributeTypeAndValue attributeTypeAndValue : issuerNameComponent) {
            if (attributeTypeAndValue.getValue().toString().length() > 64) {
                return LintResult.of(Status.WARN);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getIssuerDNNameComponent(certificate, BCStyle.SURNAME.getId()).isEmpty();
    }

}
