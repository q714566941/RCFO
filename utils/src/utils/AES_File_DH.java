package utils;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.SCPClient;


public class AES_File_DH {
	
	public AES_File_DH() {
		super();
	}
	
	static byte[] clientPublicKey = null;
	static byte[] serverPublicKey = new byte[230];   
	static byte[] clientPrivateKey = null;
	static byte[] localKey = null;
	SecretKey key;

	public static  void initKey() throws Exception{
		//gengerate client key pair
		Map<String, Object> keyMap1 = DHCoder.initKey();
		clientPublicKey = DHCoder.getPublicKey(keyMap1);
		clientPrivateKey = DHCoder.getPrivateKey(keyMap1);
		
		System.out.println("clientPublicKey:\n" + Base64.encodeBase64String(clientPublicKey));
		System.out.println("clientPrivateKey:\n" + Base64.encodeBase64String(clientPrivateKey));
		
		//Building Server's local key pair from Client's public key   !!!
		
		
//		localKey = DHCoder.getSecretKey(serverPublicKey, clientPrivateKey);    
//		System.out.println("client's local key:\n" + Base64.encodeBase64String(localKey));
	}
	
	public static void initLocalKey() throws Exception {
		//
		initKey();
		
		Socket socket = new Socket("192.168.15.1", 8888);
		//get socket outputstream: give server publickey
		OutputStream outputStream = socket.getOutputStream();
		DataOutputStream dataOutputStream  = new DataOutputStream(outputStream);
		int cpkLength = clientPublicKey.length;
		System.out.println("cpkLength is: " + cpkLength);
		if(cpkLength == 226){
			dataOutputStream.writeInt(0);
		}
		else {
			dataOutputStream.writeInt(1);
		}
		dataOutputStream.write(clientPublicKey, 0, clientPublicKey.length);
		dataOutputStream.flush();
		socket.shutdownOutput();
		
		//get socket inputstream: get server publickey
		InputStream inputStream = socket.getInputStream();
		DataInputStream dataInputStream = new DataInputStream(inputStream);
		int flagLength = dataInputStream.readInt();
		System.out.println("flagLength: " + flagLength);
		if(flagLength == 0)
			dataInputStream.readFully(serverPublicKey, 0, 226);
		else {
			dataInputStream.readFully(serverPublicKey, 0, 227);
		}
		
		//generate local key
		while(serverPublicKey != null){
			System.out.println("serverPublicKey:\n" + Base64.encodeBase64String(serverPublicKey));
			localKey = DHCoder.getSecretKey(serverPublicKey, clientPrivateKey);    
			System.out.println("client's local key:\n" + Base64.encodeBase64String(localKey));
			break;
		}
		socket.shutdownInput();
		dataInputStream.close();
		socket.close();
		
	}
	
	//encrypt
	private static void encrypt() throws Exception {
		String sourcePath = "/tmp/SGXindex";
		String destPath = "/tmp/SGXindex_encrypt";
		
		SecretKey secretKey = new SecretKeySpec(localKey, "AES");
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		
		File sourceFile = new File(sourcePath);
//		while(!sourceFile.exists()){
//			Thread.currentThread();
//			Thread.sleep(10000);  //write transmit
//		}
		File destFile = new File(destPath);
		InputStream inputStream = null;
		OutputStream outputStream = null;
		try{
			
			
			inputStream = new FileInputStream(sourceFile);
			outputStream = new FileOutputStream(destFile);
			CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
			byte[] buffer = new byte[1024];
			int r;
			while((r = inputStream.read(buffer)) >= 0){
				cipherOutputStream.write(buffer, 0, r);
			}
			cipherOutputStream.close();
		}catch(Exception e){
			e.printStackTrace();
		}finally{
			try{
				inputStream.close();
				outputStream.close();
			}catch(Exception e){
				e.printStackTrace();
			}
			}
		System.out.println("Encrypt successfully!");
	}
	
	//transmit
	public static void transmit() {
		String dataServerIp = "192.168.15.1";
		String dataServerUsername = "master";
		String dataServerPassword = "xidian";
		String dataServerDestDir = "/tmp";
		String localFile = "/tmp/SGXindex_encrypt";
		
		Connection connection = new Connection(dataServerIp);
		try {
			connection.connect();
			boolean isAuthenticated = connection.authenticateWithPassword(dataServerUsername, dataServerPassword);
			if(isAuthenticated == false)
				System.out.println("Authentication failed!");
			else {
				SCPClient client = new SCPClient(connection);
				client.put(localFile, dataServerDestDir);
				connection.close();
				System.out.println("Transmit successfully!");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) throws Exception {
		/**
		 * generate local key;
		 * encrypt
		 * transmit
		 */
		
		//initlocakey
		initLocalKey();
		
		//encrypt
		encrypt();
		
		//transmit
		transmit();
	}
}