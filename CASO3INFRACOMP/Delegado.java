import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.interfaces.DHPrivateKey;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.rmi.server.UID;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

import java.security.MessageDigest;
import java.security.Key;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Mac;
import java.util.Arrays;


public class Delegado implements Runnable {

    private Socket clientSocket;
    private Map<Integer, String> tabla_paquetes;

    public Delegado(Socket socket,  Map<Integer, String> tabla_paquetes) {
        this.clientSocket = socket;
        this.tabla_paquetes = tabla_paquetes;
;
    }

    @Override
    public void run() {
        try (BufferedReader lector = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter escritor = new PrintWriter(clientSocket.getOutputStream(), true)) {
            
            boolean AnsHandhsake = handshake(lector, escritor);
            if (AnsHandhsake == true) {}


            // Ahora puedes usar symmetricKey para cifrado y hmacKey para HMAC

             // Leer datos encriptados y HMACs desde el cliente



        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    public String verificarYProcesarDatos(byte[] encryptedUID, byte[] uidHmac, byte[] encryptedPackageId, 
                                           byte[] packageIdHmac, byte[] iv, SecretKey hmacKey, SecretKey symmetricKey) throws Exception {
        // Verificar HMAC de UID
        Mac hmacSha384 = Mac.getInstance("HmacSHA384");
        hmacSha384.init(hmacKey);

        // Computar y verificar HMAC de UID
        byte[] computedUidHmac = hmacSha384.doFinal(encryptedUID);
        System.out.println("_------------");
        System.out.println(hmacKey.toString());
        System.out.println("_------------");

        if (!Arrays.equals(computedUidHmac, uidHmac)) {
        System.out.println("HMAC de UID no coincide. Mensaje posiblemente alterado.");
        return "0";
        }

        // Computar y verificar HMAC de package_id
        byte[] computedPackageIdHmac = hmacSha384.doFinal(encryptedPackageId);
        if (!Arrays.equals(computedPackageIdHmac, packageIdHmac)) {
            System.out.println("HMAC de package_id no coincide. Mensaje posiblemente alterado.");
            return "0";
        }
        System.out.println("PASEEE :)");

        // Configuración para desencriptación usando AES/CBC/PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey, ivSpec);

        // Desencriptar UID
        byte[] uidBytes = cipher.doFinal(encryptedUID);
        String uid = new String(uidBytes, StandardCharsets.UTF_8);
        System.out.println("UID desencriptado: " + uid);

        // Desencriptar package_id
        cipher.init(Cipher.DECRYPT_MODE, symmetricKey, ivSpec); // Re-iniciar para el package_id
        byte[] packageIdBytes = cipher.doFinal(encryptedPackageId);
        String packageId = new String(packageIdBytes, StandardCharsets.UTF_8);
        System.out.println("Package ID desencriptado: " + packageId);


        // Procesar el requerimiento: aquí puede implementar la lógica para buscar el estado del paquete
        return verificarEstadoPaquete(uid, packageId);
    }

    // Simulación de la consulta al estado del paquete (dummy function)
    private String verificarEstadoPaquete(String uid, String packageId) {
        return tabla_paquetes.get(Integer.parseInt(packageId)); // Para simplificar
    }

    private void enviarEstadoEncriptado(String estado, PrintWriter escritor, byte[] iv, SecretKey symmetricKey, SecretKey hmacKey) throws Exception {
        // Encriptar el estado del paquete

        System.out.println("estado es");
        System.out.println(estado);
        System.out.println("-----------");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, ivSpec);
        byte[] EstadoEncrypted = cipher.doFinal(estado.getBytes());
        String estadoEncriptadoBase64 = Base64.getEncoder().encodeToString(EstadoEncrypted);
        
        Mac hmac = Mac.getInstance("HmacSHA384");
        hmac.init(hmacKey);
        byte[] EstadoHMAC = hmac.doFinal(estado.getBytes());
        String estadoHmacBase64= Base64.getEncoder().encodeToString(EstadoHMAC);

        // Enviar estado encriptado y HMAC al cliente
        escritor.println(estadoEncriptadoBase64);
        escritor.println(estadoHmacBase64);
    }

    public PrivateKey loadPrivateKey(String filename) throws Exception {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] privateKeyBytes = Files.readAllBytes(Paths.get("CASO3INFRACOMP/private.key"));
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            return privateKey;

        }
    

    public boolean handshake(BufferedReader lector, PrintWriter escritor) throws Exception {
        PrivateKey privateKey = loadPrivateKey("");
        System.out.println("CARGUÉ LA LLAVE");
            String requestLine = lector.readLine();
            if (requestLine.contains("SECINIT")) {
                System.out.println("HAY UN SECINIT");
                //Lee el reto
                requestLine = lector.readLine(); //requestLine pasa a ser el reto encriptado
                byte[] texto_cifrado = Base64.getDecoder().decode(requestLine);
                Cipher cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                byte[] texto_plano = cipher.doFinal(texto_cifrado);
                String reto_en_String = new String(texto_plano);
                escritor.println(reto_en_String);
                String respuesta_reto = lector.readLine();

                if (respuesta_reto.contains("OK")) {


                    System.out.println("ENTRE AL OK DE DH");

                    //Generar p, g, hellman y hacer la firma criptografica

                    String hexP = "00858386226071a5e62bff2586d6b7116c8895ce22ee6a5a392a667f47ed92cc811b286ea68f4ba12618a2bd6985daa740b7e821ee2c30a3c98186e4093014b652823cf1e33a6597f3bc0a3b18e95520aeec3b6fbd9895a47e73e82f8d12776f6df5408596e95e2105c8bba3a2d5d18c4287f841991d1df0fb25514a60130b3677";
                    BigInteger p = new BigInteger(hexP, 16); // hacemos p con el valor que nos dio en openssl
                    BigInteger g = BigInteger.valueOf(2);; // valor de g, es arbitrario
                    SecureRandom random = new SecureRandom();
                    BigInteger x = new BigInteger(256, random);
                    BigInteger Gx = g.modPow(x, p);

                    System.out.println("XXXXX ES:");
                    System.out.println(x);
                    
                    System.err.println("GENERE YA LOS PARAMETROS DH");

                    Signature signature = Signature.getInstance("SHA1withRSA");
                    signature.initSign(privateKey);
                    signature.update(p.toByteArray());
                    signature.update(g.toByteArray());
                    signature.update(Gx.toByteArray());

                    byte[] firmado = signature.sign();
                    String firmaBase64 = Base64.getEncoder().encodeToString(firmado);

                    escritor.println(g.toString());
                    escritor.println(p.toString());
                    escritor.println(Gx.toString());
                    escritor.println(firmaBase64);

                    String respuesta = lector.readLine();
                    if (respuesta.contains("OK")) {
                        System.out.println("EFECTIVAMENTE, LA SIGNATURA ME LA VERIFICARON");

                        String gYString = lector.readLine(); //lee la llave publica que envio el cliente
                        BigInteger Gy = new BigInteger(gYString);
                        BigInteger sharedSecretKey = Gy.modPow(x, p);//llave compartida


                        byte[] kBytes = sharedSecretKey.toByteArray();
                        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
                        byte[] hash = sha512.digest(kBytes);

                        //El hash se divide en dos
                        byte[] symmetricKeyBytes = new byte[32]; // 256 bits para la clave simétrica
                        byte[] hmacKeyBytes = new byte[32]; // 256 bits para la clave HMAC
                        System.arraycopy(hash, 0, symmetricKeyBytes, 0, 32);
                        System.arraycopy(hash, 32, hmacKeyBytes, 0, 32);

                        // Crear las claves secretas
                        SecretKey symmetricKey = new SecretKeySpec(symmetricKeyBytes, "AES");
                        SecretKey hmacKey = new SecretKeySpec(hmacKeyBytes, "HmacSHA384");

                        System.out.println("llave simetrica:");
                        System.out.println(symmetricKey);
                        System.out.println("hmac Key");
                        System.out.println(hmacKey);

                        //FALTA PRINTERA SYMETRIC KEY Y HMACKEY

                        String ivBase64 = lector.readLine();
                        String encryptedUIDBase64 = lector.readLine();
                        String uidHmacBase64 = lector.readLine();
                        String encryptedPackageIdBase64 = lector.readLine();
                        String packageIdHmacBase64 = lector.readLine();

                        byte[] iv = Base64.getDecoder().decode(ivBase64);

                        byte[] encryptedUID = Base64.getDecoder().decode(encryptedUIDBase64);

                        byte[] uidHmac = Base64.getDecoder().decode(uidHmacBase64);

                        byte[] encryptedPackageId = Base64.getDecoder().decode(encryptedPackageIdBase64);

                        byte[] packageIdHmac = Base64.getDecoder().decode(packageIdHmacBase64);

                        String respuestaVerificarProcesar = verificarYProcesarDatos(encryptedUID, uidHmac, encryptedPackageId, packageIdHmac, iv, hmacKey, symmetricKey);

                        if (respuestaVerificarProcesar != "0") {
                        // Obtener estado del paquete y enviarlo al cliente encriptado
                        String estadoPaquete = respuestaVerificarProcesar; // Ejemplo de estado
                        enviarEstadoEncriptado(estadoPaquete, escritor, iv, symmetricKey, hmacKey);
                        } else {
                        escritor.println("Error: HMAC no coincide o fallo de desencriptación.");
                        }


                        
    
                    }
                    else {
                        return false;
                    }
                }
            }   
            return true; // lo puse para que no genere error el metodo
    }

}

