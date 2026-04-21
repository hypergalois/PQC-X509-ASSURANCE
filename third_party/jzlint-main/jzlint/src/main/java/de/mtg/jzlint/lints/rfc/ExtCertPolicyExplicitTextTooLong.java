package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.ASN1VisibleString;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/*******************************************************************
 An explicitText field includes the textual statement directly in
 the certificate.  The explicitText field is a string with a
 maximum size of 200 characters.  Conforming CAs SHOULD use the
 UTF8String encoding for explicitText.  VisibleString or BMPString
 are acceptable but less preferred alternatives.  Conforming CAs
 MUST NOT encode explicitText as IA5String.  The explicitText string
 SHOULD NOT include any control characters (e.g., U+0000 to U+001F
 and U+007F to U+009F).  When the UTF8String or BMPString encoding
 is used, all character sequences SHOULD be normalized according
 to Unicode normalization form C (NFC) [NFC].
 *******************************************************************/

@Lint(
        name = "e_ext_cert_policy_explicit_text_too_long",
        description = "Explicit text has a maximum size of 200 characters",
        citation = "RFC 6818: 3",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC6818)
public class ExtCertPolicyExplicitTextTooLong implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<ASN1Encodable> explicitTextList = Utils.getExplicitTextList(certificate);

        for (ASN1Encodable explicitText : explicitTextList) {

            String text = null;

            if (explicitText instanceof ASN1UTF8String) {
                text = ((ASN1UTF8String) explicitText).getString();
            }

            if (explicitText instanceof ASN1BMPString) {
                text = ((ASN1BMPString) explicitText).getString();
            }

            if (explicitText instanceof ASN1VisibleString) {
                text = ((ASN1VisibleString) explicitText).getString();
            }

            if (explicitText instanceof ASN1IA5String) {
                text = ((ASN1IA5String) explicitText).getString();
            }

            if (text != null && text.length() > 200) {
                return LintResult.of(Status.ERROR);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        if (!Utils.hasCertificatePoliciesExtension(certificate)) {
            return false;
        }

        return !Utils.getExplicitTextList(certificate).isEmpty();
    }

}
