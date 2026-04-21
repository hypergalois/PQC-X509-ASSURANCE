package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.ASN1VisibleString;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/*********************************************************************
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
 *********************************************************************/
@Lint(
        name = "w_ext_cert_policy_explicit_text_includes_control",
        description = "Explicit text should not include any control characters",
        citation = "RFC 6818: 3",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC6818)
public class ExtCertPolicyExplicitTextIncludesControl implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<ASN1Encodable> explicitTextList = Utils.getExplicitTextList(certificate);

        for (ASN1Encodable explicitText : explicitTextList) {
            byte[] content = null;
            if (explicitText instanceof ASN1UTF8String) {
                try {
                    content = Utils.getContent(((ASN1UTF8String) explicitText));
                } catch (IOException ex) {
                    return LintResult.of(Status.FATAL);
                }
            }

            if (explicitText instanceof ASN1BMPString) {
                try {
                    content = Utils.getContent(((ASN1BMPString) explicitText));
                } catch (IOException ex) {
                    return LintResult.of(Status.FATAL);
                }
            }
            if (explicitText instanceof ASN1VisibleString) {
                try {
                    content = Utils.getContent(((ASN1VisibleString) explicitText));
                } catch (IOException ex) {
                    return LintResult.of(Status.FATAL);
                }
            }

            if (content == null) {
                continue;
            }

            for (int i = 0; i < content.length; i++) {
                if ((content[i] & (byte) 0x80) == 0) {
                    if ((content[i] & 0xFF) < (byte) 0x20 || (content[i] & 0xFF) == (byte) 0x7f) {
                        return LintResult.of(Status.WARN);
                    }
                } else if ((content[i] & (byte) 0x20) == 0) {
                    if ((content[i] & 0xFF) < (byte) 0x20 && (content[i + 1] & 0xFF) >= (byte) 0x80 && (content[i + 1] & 0xFF) <= (byte) 0x9f) {
                        return LintResult.of(Status.WARN);
                    }
                    i += 1;
                } else if ((content[i] & (byte) 0x10) == 0) {
                    i += 2;
                } else if ((content[i] & (byte) 0x08) == 0) {
                    i += 3;
                } else if ((content[i] & (byte) 0x04) == 0) {
                    i += 4;
                } else if ((content[i] & (byte) 0x02) == 0) {
                    i += 5;
                }
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
