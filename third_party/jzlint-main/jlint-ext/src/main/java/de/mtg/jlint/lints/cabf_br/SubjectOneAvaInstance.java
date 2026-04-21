package de.mtg.jlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/**
 * Each Name MUST NOT contain more than one instance of a given
 * AttributeTypeAndValue across all RelativeDistinguishedNames unless explicitly
 * allowed in these Requirements.
 * <p>
 * Exceptions:
 * streetAddress NOT RECOMMENDED
 * If present, MUST contain the Subject’s street address
 * information. Multiple instances MAY be present
 * <p>
 * domainComponent MAY If present, this field MUST contain a Domain Label
 * from a Domain Name. The domainComponent fields
 * for the Domain Name MUST be in a single ordered
 * sequence containing all Domain Labels from the
 * Domain Name. The Domain Labels MUST be encoded
 * in the reverse order to the on-wire representation of
 * domain names in the DNS protocol, so that the Domain
 * Label closest to the root is encoded first. Multiple
 * instances MAY be present.
 */
@Lint(
        name = "e_subject_one_ava_instance",
        description = "Each Name MUST NOT contain more than one instance of a given AttributeTypeAndValue",
        citation = "BRs: 7.1.4.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SC62_EFFECTIVE_DATE)
public class SubjectOneAvaInstance implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<String> list = new ArrayList<>();

        ASN1Sequence name = ASN1Sequence.getInstance(certificate.getSubjectX500Principal().getEncoded());
        Iterator<ASN1Encodable> iterator = name.iterator();
        while (iterator.hasNext()) {
            ASN1Set rdn = (ASN1Set.getInstance(iterator.next()));

            // assume there are no multi-valued RDNs, this is covered in another lint
            if (rdn.size() != 1) {
                continue;
            }
            Iterator<ASN1Encodable> rdnIterator = rdn.iterator();
            while (rdnIterator.hasNext()) {
                AttributeTypeAndValue attributeTypeAndValue = AttributeTypeAndValue.getInstance(rdnIterator.next());
                String oid = attributeTypeAndValue.getType().getId();

                if ("0.9.2342.19200300.100.1.25".equals(oid) || "2.5.4.9".equals(oid)) {
                    continue;
                }

                if (list.contains(oid)) {
                    return LintResult.of(Status.ERROR, String.format("AVA of type %s is contained more than once in the subject.", oid));
                }
                list.add(oid);
            }
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }

}
