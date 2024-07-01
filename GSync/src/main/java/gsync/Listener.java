package gsync;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.function.Consumer;
import java.util.function.BiConsumer;

public class Listener {
	
	protected Consumer<String> logger;
	protected Consumer<Socket> onConnectionAccept;
	
	private ServerSocket serverSocket;
    private Thread listenerThread = null;
    
    protected final String HOST = "localhost";
    protected final int PORT = 9100;
    
    
    public Listener(Consumer<String> logger) {
    	this.logger = logger;
    	logln("Server constructor Called!");
    }
        
    private void logln(String ls) {
    	logger.accept(String.format("%s\n", ls));
    }
    
    public void installOnConnectionAccept(Consumer<Socket> paramOnConnectionAccept) {
    	this.onConnectionAccept = paramOnConnectionAccept;
    }
    
    private void bind() throws IOException {
        InetAddress byAddress = InetAddress.getByName(HOST);
        this.serverSocket = new ServerSocket(PORT, 0, byAddress);
        logln("[>] server listening ");
    }
    
    public void start() {
    	try {
    		bind();
    	} catch (IOException e) {
    		logln(String.format("[x] listener start failed (%s)", e.getMessage()));
    		return;
    	}
    	listenerThread = new Thread(new Runnable() {
			public void run() {
				try {
		            while (true) {
		                Socket client = serverSocket.accept();
		                logln("[!] listener connection accepted!");
		                onConnectionAccept.accept(client);
		            }
		        } catch (IOException e) {
		            logln(String.format("[!] listener exception: %s", e.getMessage()));
		        }
			}
		});
		listenerThread.start();
    }
	
    public void stop() {
    	listenerThread.interrupt();
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                logln(String.format("[>] Listener stop: %s", e.getMessage()));
            }
        }
    	serverSocket = null;
    }

}
