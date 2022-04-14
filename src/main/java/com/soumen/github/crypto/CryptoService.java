package com.soumen.github.crypto;

import javax.xml.bind.DatatypeConverter;
import java.security.PrivateKey;

/**
 * @author Soumen Karmakar
 * @Date 14/04/2022
 */
public class CryptoService {

    private SignUtil signUtil;
    private ValidateUtil validateUtil;

    public CryptoService(String keyPath, String certPath) {
        this.signUtil = new SignUtil(keyPath);
        this.validateUtil = new ValidateUtil(certPath);
    }

    public String generateSignature(String message) {
        try {
            PrivateKey privateKey = signUtil.getPrivateKey();
            byte[] bytes = DatatypeConverter.parseHexBinary(message);
            return signUtil.sign(privateKey, bytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public boolean validateSignature(String msg, String signature) {
        try {
            return validateUtil.validate(msg, signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
