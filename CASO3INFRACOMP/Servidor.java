//SEGUNDA VERSION
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class Servidor {

    private static Map<Integer, String> tabla_paquetes;
    private static String[] estados = {"ENOFICINA", "RECOGIDO", "ENCLASIFICACION", "DESPACHADO", "ENENTREGA", "ENTREGADO", "DESCONOCIDO"};
    
        public static void main(String[] args) throws IOException {

        Random random = new Random();
        tabla_paquetes = new HashMap<>();
        for (int i = 1; i < 33; i++) {
            int indiceAleatorio = random.nextInt(estados.length);
            tabla_paquetes.put(i, estados[indiceAleatorio]);
        }
        System.out.println(tabla_paquetes);

        int port = 8080; // Server port
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server listening on port " + port);
        
    

        while (true) {
            Socket clientSocket = serverSocket.accept();
            new Thread(new Delegado(clientSocket, tabla_paquetes)).start();
        }
    }
}
