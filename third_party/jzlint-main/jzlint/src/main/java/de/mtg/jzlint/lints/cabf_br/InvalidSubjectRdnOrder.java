package de.mtg.jzlint.lints.cabf_br;

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

@Lint(
        name = "e_invalid_subject_rdn_order",
        description = "Subject field attributes (RDNs) SHALL be encoded in a specific order",
        citation = "BRs: 7.1.4.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_7_1_Date)
public class InvalidSubjectRdnOrder implements JavaLint {

    private static List<String> OID_ORDER_LIST = new ArrayList<>();

    static {

        OID_ORDER_LIST.add("0.9.2342.19200300.100.1.25");
        OID_ORDER_LIST.add("2.5.4.6");
        OID_ORDER_LIST.add("2.5.4.8");
        OID_ORDER_LIST.add("2.5.4.7");
        OID_ORDER_LIST.add("2.5.4.17");
        OID_ORDER_LIST.add("2.5.4.9");
        OID_ORDER_LIST.add("2.5.4.10");
        OID_ORDER_LIST.add("2.5.4.4");
        OID_ORDER_LIST.add("2.5.4.42");
        OID_ORDER_LIST.add("2.5.4.11");
        OID_ORDER_LIST.add("2.5.4.3");
    }

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<String> list = new ArrayList<>();
        List<String> orderedListCopy = new ArrayList<>(OID_ORDER_LIST);

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
                String lastElement = null;
                if (!list.isEmpty()) {
                    lastElement = list.get(list.size() - 1);
                }
                // ignore two appearances, this is covered in another lint
                if (OID_ORDER_LIST.contains(oid) && !oid.equals(lastElement)) {
                    list.add(oid);
                }
            }
        }

        // remove all elements from the reference list that were not found in subjectDN
        for (String oid : OID_ORDER_LIST) {
            if (!list.contains(oid)) {
                orderedListCopy.remove(oid);
            }
        }

        // ... the remaining lists must be identical
        if (list.equals(orderedListCopy)) {
            return LintResult.of(Status.PASS);
        } else {
            return LintResult.of(Status.ERROR);
        }

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }

}
