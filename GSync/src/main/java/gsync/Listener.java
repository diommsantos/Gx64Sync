package gsync;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.function.Consumer;

public class Listener {
	
	protected Logger logger;
	protected ConfigManager configManager;
	protected Consumer<Socket> onConnectionAccept;
	
	private ServerSocket serverSocket;
    private Thread listenerThread = null;
    
    protected final String HOST = ConfigManager.getConfig("GSYNC_HOST", "localhost");
    protected final int PORT = ConfigManager.getConfig("GSYNC_PORT", 9100);
    
    
    public Listener(Logger logger) {
    	Listener self = this;
    	this.logger = new Logger() {
        	public void log(String s) {
        		logger.log(self.getClass().getSimpleName()+": "+s);
        	}
        	
        	public void logError(String s) {
        		logger.logError(self.getClass().getSimpleName()+": "+s);
        	}
        	
        	public void logln(String s) {
        		logger.logln(self.getClass().getSimpleName()+": "+s);
        	}
        	
        	public void loglnError(String s) {
        		logger.loglnError(self.getClass().getSimpleName()+": "+s);
        	}
        };
        this.configManager = new ConfigManager(logger);    }
            
    public void installOnConnectionAccept(Consumer<Socket> paramOnConnectionAccept) {
    	this.onConnectionAccept = paramOnConnectionAccept;
    }
    
    private void bind() throws IOException {
        InetAddress byAddress = InetAddress.getByName(HOST);
        this.serverSocket = new ServerSocket(PORT, 0, byAddress);
        logger.logln("Listening for connections!");
    }
    
    public void start() {
    	try {
    		bind();
    	} catch (IOException e) {
    		logger.loglnError( e.getMessage());
    		return;
    	}
    	listenerThread = new Thread(new Runnable() {
			public void run() {
				try {
		            while (true) {
		                Socket client = serverSocket.accept();
		                logger.logln("Connection accepted!");
		                onConnectionAccept.accept(client);
		            }
		        } catch (IOException e) {
					if(e.getMessage().equals("Socket closed"))
		        		return;
		            logger.loglnError(e.getMessage());
		        }
			}
		});
		listenerThread.start();
    }
	
    public void stop() {
        try {
            serverSocket.close();
            listenerThread.join();
        } catch (IOException | InterruptedException e) {
            logger.loglnError(e.getMessage());
        }
    }

}
