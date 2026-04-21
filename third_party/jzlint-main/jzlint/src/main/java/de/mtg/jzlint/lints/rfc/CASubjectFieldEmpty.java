package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 RFC 5280: 4.1.2.6
 The subject field identifies the entity associated with the public
 key stored in the subject public key field.  The subject name MAY be
 carried in the subject field and/or the subjectAltName extension.  If
 the subject is a CA (e.g., the basic constraints extension, as
 discussed in Section 4.2.1.9, is present and the value of cA is
 TRUE), then the subject field MUST be populated with a non-empty
 distinguished name matching the contents of the issuer field (Section
 4.1.2.4) in all certificates issued by the subject CA.
 ************************************************/
@Lint(
        name = "e_ca_subject_field_empty",
        description = "The subject field of a CA certificate MUST have a non-empty distinguished name",
        citation = "RFC 5280: 4.1.2.6",
        source = Source.RFC2459,
        effectiveDate = EffectiveDate.RFC2459)
public class CASubjectFieldEmpty implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        byte[] encodedSubjectDN = certificate.getSubjectX500Principal().getEncoded();
        X500Name x500Name = X500Name.getInstance(encodedSubjectDN);
        if (x500Name.getRDNs().length > 0) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isCA(certificate);
    }

}
