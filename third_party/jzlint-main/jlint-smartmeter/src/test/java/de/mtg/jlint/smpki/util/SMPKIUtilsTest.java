package de.mtg.jlint.smpki.util;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.smpki.CAExtension;

import static org.junit.jupiter.api.Assertions.*;

class SMPKIUtilsTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void testIsGWACertificate()
            throws CertificateException, NoSuchAlgorithmException, IOException, OperatorCreationException, NoSuchProviderException {
        {
            X509Certificate certificate = caExtension.createEnduserCertificate("CN=ORG.GWA.EXT, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            assertTrue(SMPKIUtils.isGWACertificate(certificate));
            assertTrue(SMPKIUtils.isSMPKIEnduserCertificate(certificate));

            assertFalse(SMPKIUtils.isSMGWCertificate(certificate));
            assertFalse(SMPKIUtils.isEMTCertificate(certificate));
            assertFalse(SMPKIUtils.isGWHCertificate(certificate));
        }

        {
            X509Certificate certificate = caExtension.createEnduserCertificate("CN=ORG.GWA, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            assertTrue(SMPKIUtils.isGWACertificate(certificate));
            assertTrue(SMPKIUtils.isSMPKIEnduserCertificate(certificate));

            assertFalse(SMPKIUtils.isSMGWCertificate(certificate));
            assertFalse(SMPKIUtils.isEMTCertificate(certificate));
            assertFalse(SMPKIUtils.isGWHCertificate(certificate));
        }
    }

    @Test
    void testIsGWHCertificate()
            throws CertificateException, NoSuchAlgorithmException, IOException, OperatorCreationException, NoSuchProviderException {
        {
            X509Certificate certificate = caExtension.createEnduserCertificate("CN=ORG.GWH.EXT, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            assertTrue(SMPKIUtils.isGWHCertificate(certificate));
            assertTrue(SMPKIUtils.isSMPKIEnduserCertificate(certificate));

            assertFalse(SMPKIUtils.isSMGWCertificate(certificate));
            assertFalse(SMPKIUtils.isEMTCertificate(certificate));
            assertFalse(SMPKIUtils.isGWACertificate(certificate));
        }

        {
            X509Certificate certificate = caExtension.createEnduserCertificate("CN=ORG.GWH, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            assertTrue(SMPKIUtils.isGWHCertificate(certificate));
            assertTrue(SMPKIUtils.isSMPKIEnduserCertificate(certificate));

            assertFalse(SMPKIUtils.isSMGWCertificate(certificate));
            assertFalse(SMPKIUtils.isEMTCertificate(certificate));
            assertFalse(SMPKIUtils.isGWACertificate(certificate));
        }
    }

    @Test
    void testIsEMTCertificate()
            throws CertificateException, NoSuchAlgorithmException, IOException, OperatorCreationException, NoSuchProviderException {
        {
            X509Certificate certificate = caExtension.createEnduserCertificate("CN=ORG.EMT.EXT, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            assertTrue(SMPKIUtils.isEMTCertificate(certificate));
            assertTrue(SMPKIUtils.isSMPKIEnduserCertificate(certificate));

            assertFalse(SMPKIUtils.isSMGWCertificate(certificate));
            assertFalse(SMPKIUtils.isGWHCertificate(certificate));
            assertFalse(SMPKIUtils.isGWACertificate(certificate));
        }

        {
            X509Certificate certificate = caExtension.createEnduserCertificate("CN=ORG.EMT, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            assertTrue(SMPKIUtils.isEMTCertificate(certificate));
            assertTrue(SMPKIUtils.isSMPKIEnduserCertificate(certificate));

            assertFalse(SMPKIUtils.isSMGWCertificate(certificate));
            assertFalse(SMPKIUtils.isGWHCertificate(certificate));
            assertFalse(SMPKIUtils.isGWACertificate(certificate));
        }
    }


    @Test
    void testIsSMGWCertificate()
            throws CertificateException, NoSuchAlgorithmException, IOException, OperatorCreationException, NoSuchProviderException {
        {
            X509Certificate certificate = caExtension.createEnduserCertificate("CN=ORG.SMGW.EXT, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            assertTrue(SMPKIUtils.isSMGWCertificate(certificate));
            assertTrue(SMPKIUtils.isSMPKIEnduserCertificate(certificate));

            assertFalse(SMPKIUtils.isEMTCertificate(certificate));
            assertFalse(SMPKIUtils.isGWHCertificate(certificate));
            assertFalse(SMPKIUtils.isGWACertificate(certificate));
        }

        {
            X509Certificate certificate = caExtension.createEnduserCertificate("CN=ORG.SMGW, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");
            assertTrue(SMPKIUtils.isSMGWCertificate(certificate));
            assertTrue(SMPKIUtils.isSMPKIEnduserCertificate(certificate));

            assertFalse(SMPKIUtils.isEMTCertificate(certificate));
            assertFalse(SMPKIUtils.isGWHCertificate(certificate));
            assertFalse(SMPKIUtils.isGWACertificate(certificate));
        }
    }

}