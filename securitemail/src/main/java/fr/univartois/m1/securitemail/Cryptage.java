package fr.univartois.m1.securitemail;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Cryptage {

	public static String crypterMessage(PrivateKey key, String msg) throws InvalidKeyException,
			NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key); // Chiffrement avec la clé privée
		return Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes()));
	}

	public static String decrypterMessage(PublicKey key, String msg)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, key); // Déchiffrement avec la clé publique
		return new String(cipher.doFinal(Base64.getDecoder().decode(msg)), "UTF-8");
	}

}