package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/*******************************************************************
 https://tools.ietf.org/html/rfc6818#section-3
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
        name = "w_ext_cert_policy_explicit_text_not_utf8",
        description = "Compliant certificates should use the utf8string encoding for explicitText",
        citation = "RFC 6818: 3",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC6818)
public class ExtCertPolicyExplicitTextNotUtf8 implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<ASN1Encodable> explicitTextList = Utils.getExplicitTextList(certificate);

        for (ASN1Encodable explicitText : explicitTextList) {
            try {
                if (explicitText.toASN1Primitive().getEncoded(ASN1Encoding.DER)[0] != 12) {
                    return LintResult.of(Status.WARN);
                }
            } catch (IOException ex) {
                return LintResult.of(Status.FATAL);
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
