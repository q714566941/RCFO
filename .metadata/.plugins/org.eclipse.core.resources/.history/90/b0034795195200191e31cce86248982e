package decrypt;

import java.util.HashMap;
import java.util.Map;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public abstract class DHCoder {
	// Asymmetric encryption algorithm
	private static final String KEY_ALGORITHM =  "DH";
	
	//Symmetric encryption algorithm: AES/DES/DESede
	private static final String SELECT_ALGORITHM = "AES";                     
	
	//Key length
	private static final int KEY_SIZE = 512;
	
	//P key
	private static final String PUBLIC_KEY = "DHPublicKey";
	private static final String PRIVATE_KEY = "DHPrivateKey";
	
	/**
	 * Initialization A key
	 * @return Map A's key
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception{
		//Instantiated key generator 
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		
		//Initialization key generator
		keyPairGenerator.initialize(KEY_SIZE);
		
		//Generate a key pair
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		DHPublicKey publicKey = (DHPublicKey)keyPair.getPublic();
		DHPrivateKey privateKey = (DHPrivateKey)keyPair.getPrivate();
		
		//Store the key pair in the Map
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
	/**
	 * Initialization B key
	 * @return Map B's key
	 * @throws Exception
	 */
	public static Map<String, Object> initKey(byte[] key) throws Exception{
		//Parse A's public key
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);
		
		//Instantiate key factory
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		
		//generate public key
		PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
		
		//Building B's key from A' public key
		DHParameterSpec dhParameterSpec = ((DHPublicKey)pubKey).getParams();
		
		//Instantiate key generator
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		//Initialization key generator
		keyPairGenerator.initialize(KEY_SIZE);
		
		//generate a key pair
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		//B's public key
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		
		//Store the key pair in the Map
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
	/**
	 * Encrypt
	 * @param data: for encrypting data
	 * @param key: key
	 * @return byte[] encrypted data
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] data, byte[] key) throws Exception{
		//generate local key
		SecretKey secretKey = new SecretKeySpec(key, SELECT_ALGORITHM);
		
		//encrypt data
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return cipher.doFinal(data);
	}
	/**
	 * decrypt
	 * @param key  key
	 * @return byte[] decrypted data
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
		//generate local key
		SecretKey secretKey = new SecretKeySpec(key,  SELECT_ALGORITHM);
		
		//decrypt data
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		return cipher.doFinal(data);
	}
	/**
	 * generate key
	 * @param publicKey 
	 * @param privateKey
	 * @return byte[]  local key
	 * @throws Exception
	 */
	public static byte[] getSecretKey(byte[] publicKey, byte[] privateKey) throws Exception {
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		//another way :(
		
		
		//Initial public key
		
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKey);
		PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);
//		PKCS8EncodedKeySpec pkcs8KeySpec1 = new PKCS8EncodedKeySpec(privateKey);
//		PublicKey pubKey = keyFactory.generatePublic(pkcs8KeySpec1);
		
		//Initial private key
		PKCS8EncodedKeySpec pkcs8KeySpec2 = new PKCS8EncodedKeySpec(privateKey);
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec2);
		
		//Instantiation
		KeyAgreement keyAgree = KeyAgreement.getInstance(keyFactory.getAlgorithm());
		keyAgree.init(priKey);
		keyAgree.doPhase(pubKey, true);
		
		//generate local key
		SecretKey secretKey = keyAgree.generateSecret(SELECT_ALGORITHM);
		return secretKey.getEncoded();
	}
	/**
	 * get private key
	 * @param keyMap  
	 * @return byte[]  private key
	 * @throws Exception
	 */
	public static byte[] getPrivateKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PRIVATE_KEY);
		return key.getEncoded();
	}
	/**
	 * get public key
	 * @param keyMap
	 * @return byte[] public key
	 * @throws Exception
	 */
	public static byte[] getPublicKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PUBLIC_KEY);
		return key.getEncoded();
	}
}

