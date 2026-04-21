package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


/*************************************************************************
 When the subjectAltName extension contains a URI, the name MUST be
 stored in the uniformResourceIdentifier (an IA5String).  The name
 MUST NOT be a relative URI, and it MUST follow the URI syntax and
 encoding rules specified in [RFC3986].  The name MUST include both a
 scheme (e.g., "http" or "ftp") and a scheme-specific-part.  URIs that
 include an authority ([RFC3986], Section 3.2) MUST include a fully
 qualified domain name or IP address as the host.  Rules for encoding
 Internationalized Resource Identifiers (IRIs) are specified in
 Section 7.4.
 *************************************************************************/

@Lint(
        name = "e_ext_san_uri_relative",
        description = "When the subjectAlternateName extension is present and a URI is used, the name MUST NOT be a relative URI",
        citation = "RFC 5280: 4.2.1.6",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class ExtSanUriRelative implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawSAN = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

        return ExtSanUriRelative.isURIAbsolute(rawSAN);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId());
    }

    protected static LintResult isURIAbsolute(byte[] rawContent) {
        try {
            List<GeneralName> uris = Utils.getUniformResourceIdentifiers(rawContent);

            for (GeneralName generalName : uris) {
                String uriString = generalName.getName().toString();

                try {
                    URI uri = new URI(uriString);

                    if (!uri.isAbsolute()) {
                        return LintResult.of(Status.ERROR);
                    }
                } catch (URISyntaxException ex) {
                    return LintResult.of(Status.ERROR);
                }
            }
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
        return LintResult.of(Status.PASS);
    }
}
