package gsync;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.function.Consumer;
import java.util.concurrent.CountDownLatch;
import java.util.function.BiConsumer;

public class ClientHandler {
	
	protected Logger logger;
	protected BiConsumer<String, ClientHandler> receiver;
	protected Consumer<ClientHandler> sessionStopper;
	protected BiConsumer<ClientHandler, IOException> errorRecuperator;
	protected Object receiverArg;
	
	private CountDownLatch active;
	private Socket clientSocket;
	PrintWriter out;
    BufferedReader in;
    
    private Thread clientThread = null;
	
	ClientHandler(Socket client, Logger logger, Consumer<ClientHandler> sessionStopper, BiConsumer<ClientHandler, IOException> errorRecuperator){
		ClientHandler self = this;
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
		this.clientSocket = client;
		this.sessionStopper = sessionStopper;
		this.errorRecuperator = errorRecuperator;
	}
		
	public void installReceiver(BiConsumer<String, ClientHandler> paramReceiver) {
		this.receiver = paramReceiver;
	}
	
	public void start() {
		active = new CountDownLatch(1);
		final ClientHandler self = this;
		this.clientThread = new Thread(new Runnable() {
			
			@Override
			public void run(){
				String inputLine;

		        try {
		            out = new PrintWriter(clientSocket.getOutputStream(), true);
		            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
		            active.countDown();
		            while ((inputLine = in.readLine()) != null) {
		                receiver.accept(inputLine, self);
		            }
		            
		            in.close();
		            out.close();
		            sessionStopper.accept(self);
		        } catch (IOException e) {
		        	if(e.getMessage().equals("Socket closed")) {
		        		sessionStopper.accept(self);
		        		return;
		        	}
		            logger.loglnError(e.getMessage());
		            errorRecuperator.accept(self, e);
		        }
			}
		});
		clientThread.start();
		
		try {
			active.await();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public void stop() {
		try {
			clientSocket.close();
			clientThread.join();
		} catch (IOException | InterruptedException e) {
            logger.loglnError(e.getMessage());
        }
	}
	
	public void send(String data) {
		out.print(data+"\n");
		out.flush();
	}


}
