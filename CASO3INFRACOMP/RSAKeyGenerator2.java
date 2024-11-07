import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAKeyGenerator2 {

    public static void main(String[] args) {
        try {
            // Genera el par de claves RSA
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048); // Puedes cambiar el tamaño a 3072 o 4096 si necesitas más seguridad
            KeyPair pair = keyGen.generateKeyPair();
            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();

            // Guarda la clave pública en un archivo
            try (FileOutputStream fos = new FileOutputStream("public.key")) {
                fos.write(publicKey.getEncoded());
            }

            // Guarda la clave privada en un archivo
            try (FileOutputStream fos = new FileOutputStream("private.key")) {
                fos.write(privateKey.getEncoded());
            }

            System.out.println("Claves generadas y guardadas en archivos.");

        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }
}
