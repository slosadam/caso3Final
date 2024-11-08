import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PrivateKey;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;

public class Cliente {

    public static final int PUERTO = 8080;
    public static final String SERVIDOR = "localhost";

    private static BigInteger privateExponentY;
    private static BigInteger sharedSecretKey;
    private static SecretKey symmetricKey;
    private static SecretKey hmacKey;
    private static IvParameterSpec ivSpecgeneral = null;
    
    
    public static void main(String[] args) throws Exception {
		
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		
		System.out.println("Comienza cliente");
		
		try {
			socket = new Socket(SERVIDOR, PUERTO);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		
		escritor.println("SECINIT");

        PublicKey publicKey = loadPublicKey("CASO3INFRACOMP/public.key");

        String retoBytes = "SOFIA ME CAE MUY MAL";
         // Genero el reto

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] textoCifrado = cipher.doFinal(retoBytes.getBytes());
        String textoCifradoBase64 = Base64.getEncoder().encodeToString(textoCifrado);
        escritor.println(textoCifradoBase64);
        


		String retoDesencriptado = lector.readLine();
        if (new String(retoBytes).contains(retoDesencriptado)) {
            escritor.println("OK");

            BigInteger g = new BigInteger(lector.readLine()); //BitArray del BigInteger
            BigInteger p = new BigInteger(lector.readLine()); //El P viene en un string hex hay que transformalo
            BigInteger Gx = new BigInteger(lector.readLine()); //BitArray del BigInteger
            byte[] firma = Base64.getDecoder().decode(lector.readLine()); //Firma


            System.out.println("ANTES DE ENTRAR AL VERIFICADOR");

            Signature verificador = Signature.getInstance("SHA1withRSA");
            verificador.initVerify(publicKey);

            verificador.update(p.toByteArray());
            verificador.update(g.toByteArray());
            verificador.update(Gx.toByteArray());
            
            if(verificador.verify(firma)) {
                escritor.println("OK");
                System.out.println("verifique la firma");
                ArrayList<BigInteger> devuelta =  crearKeySecretaCompartida(g, p, Gx, escritor);
                BigInteger privateExponentY = devuelta.get(0);
                BigInteger Gy = devuelta.get(1);


                escritor.println(Gy.toString()); // aqui la llave publica del cliente se manda al servidor
                sharedSecretKey = Gx.modPow(privateExponentY, p); // clave compartida secreta: K = (G^x)^y mod p



                ArrayList<SecretKey> retorno = deriveKeys(sharedSecretKey);
                SecretKey llave_simetrica = retorno.get(0);
                SecretKey hmac = retorno.get(1);

                //Generar UID y package id
                Random random = new Random();
                int UID = random.nextInt(100);
                System.out.println("el uid es:");
                System.out.println(UID);
                System.out.println("-------------");


                int package_id = random.nextInt(32);

                System.out.println("el package_id es:");
                System.out.println(package_id);
                System.out.println("-------------");
                //

                enviarDatosCifrados(String.valueOf(UID), String.valueOf(package_id), escritor, llave_simetrica, hmac);
                recibirYVerificarEstado(lector, ivSpecgeneral, llave_simetrica, hmac);
            }
            else {
                escritor.println("ERROR");
            }
        }
        else {
            escritor.println("ERROR");
        }
		
		socket.close();
		escritor.close();
		lector.close();
	}
    
    public static PublicKey loadPublicKey(String filename) throws Exception {
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get("/Users/juanpablorivera/Desktop/CASO3/caso3Infracomp/CASO3INFRACOMP/public.key"));
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            return publicKey;

    }

    public static ArrayList<BigInteger> crearKeySecretaCompartida(BigInteger g, BigInteger p, BigInteger Gx, PrintWriter escritor) {
        SecureRandom yRandom = new SecureRandom();
        BigInteger privateExponentY = new BigInteger(256, yRandom); // el exponente tiene 256 bits
        // clave pública cliente: G^y mod p
        BigInteger Gy = g.modPow(privateExponentY, p); 
        ArrayList<BigInteger> Devuelta = new ArrayList<>();
        Devuelta.add(privateExponentY);
        Devuelta.add(Gy);
        return Devuelta;

    }

    public static ArrayList<SecretKey> deriveKeys(BigInteger sharedSecretKey) {
        try {
            byte[] kBytes = sharedSecretKey.toByteArray();
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hash = sha512.digest(kBytes);

            // Dividir el hash en dos mitades
            byte[] symmetricKeyBytes = new byte[32]; // 256 bits para la clave simétrica
            byte[] hmacKeyBytes = new byte[32]; // 256 bits para la clave HMAC
            System.arraycopy(hash, 0, symmetricKeyBytes, 0, 32);
            System.arraycopy(hash, 32, hmacKeyBytes, 0, 32);

            // Crear las claves secretas
            SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes, "AES");
            SecretKey hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA384");
            System.out.println("Clave simétrica derivada: " + new BigInteger(1, symmetricKey.getEncoded()).toString(16));
            System.out.println("Clave HMAC derivada: " + new BigInteger(1, hmacKey.getEncoded()).toString(16));
            ArrayList<SecretKey> retorno = new ArrayList<>();
            retorno.add(symmetricKey);
            retorno.add(hmacKey);
            return retorno;
       
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void enviarDatosCifrados(String UID, String package_id, PrintWriter escritor, SecretKey symmetricKey, SecretKey hmacKey){
        final int GCM_TAG_LENGTH = 128; // Define la longitud del tag de autenticación en bits    
        try {
            // Inicialización de cifrado AES en modo CBC con PKCS5Padding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16]; // Vector de inicialización para CBC
            new SecureRandom().nextBytes(iv);


            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            ivSpecgeneral = ivSpec;

            // Cifrar UID
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, ivSpec);
            byte[] UIDEncrypted = cipher.doFinal(UID.getBytes(StandardCharsets.UTF_8));
            String UIDEncryptedBase64 = Base64.getEncoder().encodeToString(UIDEncrypted);

            // Cifrar package_id
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, ivSpec);
            byte[] packageIdEncrypted = cipher.doFinal(package_id.getBytes(StandardCharsets.UTF_8));
            String packageIdEncryptedBase64 = Base64.getEncoder().encodeToString(packageIdEncrypted);

            // Generar HMACs para ambos
            Mac hmac = Mac.getInstance("HmacSHA384");
            hmac.init(hmacKey);

            byte[] UIDHMAC = hmac.doFinal(UIDEncrypted);
            String UIDHMACBase64 = Base64.getEncoder().encodeToString(UIDHMAC);

            byte[] packageIdHMAC = hmac.doFinal(packageIdEncrypted);
            String packageIdHMACBase64 = Base64.getEncoder().encodeToString(packageIdHMAC);

            System.out.println("-----------------");
            System.out.println(hmacKey);
            System.out.println("-----------------");

            // Enviar al servidor: iv, datos cifrados y HMACs
            escritor.println(Base64.getEncoder().encodeToString(iv));
            escritor.println(UIDEncryptedBase64);
            escritor.println(UIDHMACBase64);
            escritor.println(packageIdEncryptedBase64);
            escritor.println(packageIdHMACBase64);
    } catch (Exception e) {
        e.printStackTrace();
    }
}

public static void recibirYVerificarEstado(BufferedReader lector, IvParameterSpec ivSpec, SecretKey symmetricKey, SecretKey hmacKey) {
    try {

        byte[] estadoCifrado = Base64.getDecoder().decode(lector.readLine());

        byte[] estadoHMAC = Base64.getDecoder().decode(lector.readLine());



        // Desencriptar estado
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey, ivSpec);
        byte[] estadoDescifradoBytes = cipher.doFinal(estadoCifrado);
        String estadoDescifrado = new String(estadoDescifradoBytes, StandardCharsets.UTF_8);

        // Verificar HMAC
        Mac hmac = Mac.getInstance("HmacSHA384");
        hmac.init(hmacKey);
        byte[] estadoHMACCalculado = hmac.doFinal(estadoDescifradoBytes);

        System.out.println("COMPARACION");
        System.out.println(new String (estadoDescifradoBytes));
        System.out.println(new String (estadoHMACCalculado));
        if (!MessageDigest.isEqual(estadoHMAC, estadoHMACCalculado)) {
            System.out.println("Error: HMAC del estado no coincide. El mensaje podría haber sido alterado.");
            return;
        }
        System.out.println("Estado del paquete recibido y verificado: " + estadoDescifrado);

    } catch (Exception e) {
        e.printStackTrace();
    }
}

}


    

