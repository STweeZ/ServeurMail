package fr.univartois.m1.securitemail;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hachage {

	public static byte[] hash(String str) throws UnsupportedEncodingException, NoSuchAlgorithmException {
		byte[] byteChain;
		byteChain = str.getBytes("UTF-8");
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(byteChain); // Hachage du message en SHA-256
	}

}