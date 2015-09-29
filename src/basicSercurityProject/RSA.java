package basicSercurityProject;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class RSA {
	
	public static void GenerateRSAKeys() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException 
	{
		//person A's keys
		KeyPairGenerator kpgA = KeyPairGenerator.getInstance("RSA");
		kpgA.initialize(4092);
		KeyPair kpA = kpgA.genKeyPair();
		
		KeyFactory factA = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubA = factA.getKeySpec(kpA.getPublic(),RSAPublicKeySpec.class);
		RSAPrivateKeySpec privA = factA.getKeySpec(kpA.getPrivate(),RSAPrivateKeySpec.class);
		
		saveToFile("public_A.key", pubA.getModulus(),pubA.getPublicExponent());
		saveToFile("private_A.key", privA.getModulus(),privA.getPrivateExponent());
		
		//person B's keys
		KeyPairGenerator kpgB = KeyPairGenerator.getInstance("RSA");
		kpgB.initialize(4092);
		KeyPair kpB = kpgB.genKeyPair();
		
		KeyFactory factB = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubB = factB.getKeySpec(kpB.getPublic(),RSAPublicKeySpec.class);
		RSAPrivateKeySpec privB= factB.getKeySpec(kpB.getPrivate(),RSAPrivateKeySpec.class);
		
		saveToFile("public_B.key", pubB.getModulus(),pubB.getPublicExponent());
		saveToFile("private_B.key", privB.getModulus(),privB.getPrivateExponent());
	}
	
	public static Cipher GenerateRSACipher() throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		Cipher rsaCipher;
		rsaCipher = Cipher.getInstance("RSA");
		 
		return rsaCipher;
	}
	
	public static String RSAEncryptKey(SecretKey desKey, Cipher rsaCipher) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		  PublicKey pubKey = readPubKeyFromFile("public_B.key");
		  rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
		  
		  byte[] cipherBytes;
		  String cipherStr;
		  
		  cipherBytes = rsaCipher.doFinal(desKey.getEncoded());
		  cipherStr = Base64.getEncoder().encodeToString(cipherBytes);
		  System.out.println("DES key enrypted with RSA");
		  
		  return cipherStr;
	}
	
	public static SecretKey RSADecryptKey(String cipherStr, Cipher rsaCipher) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		  PrivateKey privKey = readPrivKeyFromFile("private_B.key");
		  rsaCipher.init(Cipher.DECRYPT_MODE, privKey);
		  
		  byte[] cipherBytes;
		  byte[] bytes;
		  SecretKey desKey;
		  
		  cipherBytes = Base64.getDecoder().decode(cipherStr);
		  bytes = rsaCipher.doFinal(cipherBytes);
		  desKey = new SecretKeySpec(bytes, 0, bytes.length, "DES");
		  System.out.println("DES key decrypted with RSA");
		  
		  return desKey;
	}
	
	public static String RSASignString(String str, Cipher rsaCipher) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		PrivateKey privKey = readPrivKeyFromFile("private_A.key");
		rsaCipher.init(Cipher.ENCRYPT_MODE, privKey);
		  
		byte[] cipherBytes;
		String cipherStr;
		  
		cipherBytes = rsaCipher.doFinal(Base64.getDecoder().decode(str));
		cipherStr = Base64.getEncoder().encodeToString(cipherBytes);
		System.out.println("hash signed");
		
		return cipherStr;
	}
	
	public static String RSAUnsignString(String str, Cipher rsaCipher) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		PublicKey pubKey = readPubKeyFromFile("public_A.key");
		rsaCipher.init(Cipher.DECRYPT_MODE, pubKey);
		  
		byte[] decodedBytes;
		String decodedStr;
		  
		decodedBytes = rsaCipher.doFinal(Base64.getDecoder().decode(str));
		decodedStr = Base64.getEncoder().encodeToString(decodedBytes);
		System.out.println("hash unsigned");
		
		return decodedStr;
	}
	
	public static PublicKey readPubKeyFromFile(String keyFileName) throws IOException {
		  FileInputStream in = new FileInputStream(keyFileName);
		  ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
		  try
		  {
		    BigInteger m = (BigInteger) oin.readObject();
		    BigInteger e = (BigInteger) oin.readObject();
		    
		    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
		    
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PublicKey pubKey = fact.generatePublic(keySpec);
		    
		    return pubKey;
		  } 
		  catch (Exception e) 
		  {
		    throw new RuntimeException("Spurious serialisation error", e);
		  } 
		  finally
		  {
		    oin.close();
		  }
		}
	
	public static PrivateKey readPrivKeyFromFile(String keyFileName) throws IOException {
		  FileInputStream in = new FileInputStream(keyFileName);
		  ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
		  try
		  {
		    BigInteger m = (BigInteger) oin.readObject();
		    BigInteger e = (BigInteger) oin.readObject();
		    
		    RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
		    
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    PrivateKey privKey = fact.generatePrivate(keySpec);
		    
		    return privKey;
		  } 
		  catch (Exception e) 
		  {
		    throw new RuntimeException("Spurious serialisation error", e);
		  } 
		  finally
		  {
		    oin.close();
		  }
		}
	
	public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException 
	{
			ObjectOutputStream oout = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
			  try 
			  {
			    oout.writeObject(mod);
			    oout.writeObject(exp);
			  } 
			  catch (Exception e) 
			  {
			    throw new IOException("Unexpected error", e);
			  } 
			  finally 
			  {
			    oout.close();
			  }
			}

}
