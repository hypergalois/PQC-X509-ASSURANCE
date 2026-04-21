package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


/************************************************************************
 RFC 5280: 4.2.1.6
 When the subjectAltName extension contains a domain name system
 label, the domain name MUST be stored in the dNSName (an IA5String).
 The name MUST be in the "preferred name syntax", as specified by
 Section 3.5 of [RFC1034] and as modified by Section 2.1 of
 [RFC1123].  Note that while uppercase and lowercase letters are
 allowed in domain names, no significance is attached to the case.  In
 addition, while the string " " is a legal domain name, subjectAltName
 extensions with a dNSName of " " MUST NOT be used.  Finally, the use
 of the DNS representation for Internet mail addresses
 (subscriber.example.com instead of subscriber@example.com) MUST NOT
 be used; such identities are to be encoded as rfc822Name.  Rules for
 encoding internationalized domain names are specified in Section 7.2.
 ************************************************************************/

@Lint(
        name = "e_ext_san_space_dns_name",
        description = "The dNSName ` ` MUST NOT be used",
        citation = "RFC 5280: 4.2.1.6",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtSanSpaceDnsName implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> dnsNames = Utils.getDNSNames(certificate);

            for (String dnsName : dnsNames) {
                if (dnsName.equalsIgnoreCase(" ")) {
                    return LintResult.of(Status.ERROR);
                }
            }
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId());
    }
}
