package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.text.Normalizer;
import java.util.List;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1UTF8String;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 When the UTF8String encoding is used, all character sequences SHOULD be
 normalized according to Unicode normalization form C (NFC) [NFC].
 ************************************************/
@Lint(
        name = "w_ext_cert_policy_explicit_text_not_nfc",
        description = "When utf8string or bmpstring encoding is used for explicitText field in certificate policy, it SHOULD be normalized by NFC format",
        citation = "RFC 6818 3",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC6818)
public class ExtCertPolicyExplicitTextNotNfc implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<ASN1Encodable> explicitTextList = Utils.getExplicitTextList(certificate);

        for (ASN1Encodable explicitText : explicitTextList) {
            if (explicitText instanceof ASN1UTF8String) {
                String text = ((ASN1UTF8String) explicitText).getString();
                if (!Normalizer.isNormalized(text, Normalizer.Form.NFC)) {
                    return LintResult.of(Status.WARN);
                }
            }

            if (explicitText instanceof ASN1BMPString) {
                String text = ((ASN1BMPString) explicitText).getString();
                if (!Normalizer.isNormalized(text, Normalizer.Form.NFC)) {
                    return LintResult.of(Status.WARN);
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
