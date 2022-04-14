package com.soumen.github.crypto;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKeyStructure;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Objects;

/**
 * @author Soumen Karmakar
 * @Date 14/04/2022
 */
public class SignUtil {


    public static final String EC_ALGO = "EC";
    public static final String SHA256_ALGO = "SHA-256";
    private PrivateKey privateKey;
    private String keyPath;

    public SignUtil(String keyPath) {
        this.keyPath = keyPath;
    }

    public String sign(PrivateKey ecPrivateKey, byte[] message) throws IOException, NoSuchAlgorithmException {
        boolean flag = false;
        String secretNumber = null;
        ECPrivateKeyParameters ecPrivateKeySpec;
        ECDSASigner ecdsaSigner;
        BigInteger[] sig;
        do {
            secretNumber = generateK(message, ecPrivateKey, flag, secretNumber);
            ecPrivateKeySpec = getEcurvePriKeyParameter(ecPrivateKey);
            ecdsaSigner = new ECDSASigner();
            ecdsaSigner.init(true,
                    new ParametersWithRandom(ecPrivateKeySpec, generateSecureRandom(secretNumber)));
            sig = ecdsaSigner.generateSignature(generateHashMessage(message));
            flag = true;
        }
        while (sig[0].equals(BigInteger.ZERO) || sig[1].equals(BigInteger.ZERO));
        String rSignature = sig[0].toString(16);
        String sSignature = sig[1].toString(16);
        final String modulus = "%64s";
        rSignature = String.format(modulus, rSignature).replace(' ', '0');
        sSignature = String.format(modulus, sSignature).replace(' ', '0');
        return rSignature + sSignature;

    }

    public PrivateKey getPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        if (privateKey == null) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(BaseEncoding
                    .base64()
                    .decode(readPvtKeyFromFile(keyPath)));
            KeyFactory factory = KeyFactory.getInstance(EC_ALGO, new BouncyCastleProvider());
            privateKey = factory.generatePrivate(spec);
        }
        return privateKey;
    }


    private String readPvtKeyFromFile(String keyPath) throws IOException {
        byte[] bytes = Files.readAllBytes(Paths.get(keyPath));
        String s = new String(bytes);
        s = s.replace("-----BEGIN EC PRIVATE KEY-----", "");
        s = s.replace("-----END EC PRIVATE KEY-----", "");
        s = s.replace("-----BEGIN PRIVATE KEY-----", "");
        s = s.replace("-----END PRIVATE KEY-----", "");
        s = s.replaceAll("\\r", "");
        s = s.replaceAll("\\n", "");
        return s;
    }

    public String generateK(final byte[] message,
                            final PrivateKey privateKey,
                            final boolean isCalculated,
                            String secretNumber) throws IOException, NoSuchAlgorithmException {
        if (!isCalculated) {
            secretNumber = generatePerMessageSecretNumber(message, privateKey);
        } else {
            secretNumber = secretNumber + "00";
        }
        return secretNumber;
    }


    private String generatePerMessageSecretNumber(final byte[] message, final PrivateKey privateKey) throws IOException, NoSuchAlgorithmException {
        String pkToHex = convertPkToHex(privateKey);
        byte[] pkToByte = DatatypeConverter.parseHexBinary(pkToHex);
        byte[] concatenatedBytes = new byte[message.length + pkToByte.length];
        System.arraycopy(message, 0, concatenatedBytes, 0, message.length);
        System.arraycopy(pkToByte, 0, concatenatedBytes, message.length, pkToByte.length);
        return generateHash(concatenatedBytes);
    }


    public String generateHash(final byte[] concatenatedString) throws NoSuchAlgorithmException {
        MessageDigest md;
        md = MessageDigest.getInstance(SHA256_ALGO);
        byte[] hash = md.digest(concatenatedString);
        return new BigInteger(1, hash).toString(16);
    }

    private String convertPkToHex(final PrivateKey privateKey)
            throws IOException {
        ASN1InputStream stream = null;
        try {
            byte[] encoded = privateKey.getEncoded();
            stream = new ASN1InputStream(encoded);
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(stream.readObject());
            ECPrivateKeyStructure ec = new ECPrivateKeyStructure(
                    (ASN1Sequence) pki.getPrivateKey());
            return ec.getKey().toString(16);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            Objects.requireNonNull(stream).close();
        }
        return null;
    }


    public ECPrivateKeyParameters getEcurvePriKeyParameter(PrivateKey privateKey) {
        ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
        ECParameterSpec spec = ecPrivateKey.getParameters();
        ECDomainParameters params = new ECDomainParameters(spec.getCurve(),
                spec.getG(), spec.getN(), spec.getH());
        return new ECPrivateKeyParameters(ecPrivateKey.getD(), params);
    }

    public SecureRandom generateSecureRandom(String secretNumber) {
        final String modulus = "%64s";
        secretNumber = String.format(modulus, secretNumber).replace(' ', '0');
        return new FixedSecureRandom(Hex.decode(secretNumber));
    }


    public byte[] generateHashMessage(final byte[] message) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance(SHA256_ALGO).digest(message);
    }

}
