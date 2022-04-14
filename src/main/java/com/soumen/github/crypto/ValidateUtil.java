package com.soumen.github.crypto;

import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * @author Soumen Karmakar
 * @Date 14/04/2022
 */
public class ValidateUtil {
    public static final String X509 = "X.509";
    private String certPath;
    private X509Certificate x509Certificate;

    public ValidateUtil(String certPath) {
        this.certPath = certPath;
        this.x509Certificate = loadX509Certificate();
    }

    public X509Certificate loadX509Certificate() {
        try (FileInputStream in = new FileInputStream(certPath)) {
            CertificateFactory instance = CertificateFactory.getInstance(X509);
            return (X509Certificate) instance.generateCertificate(in);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean validate(String message, String signature) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, SignatureException, InvalidKeyException {
        byte[] msg = DatatypeConverter.parseHexBinary(message);
        byte[] signByte = SignatureEncoder.generateAsnSignatureArray(signature);

        Signature sign = Signature.getInstance("SHA256withECDSA", "SunEC");

        sign.initVerify(x509Certificate.getPublicKey());
        sign.update(msg);
        final boolean verificationStatus = sign.verify(signByte);
        return verificationStatus;
    }
}
