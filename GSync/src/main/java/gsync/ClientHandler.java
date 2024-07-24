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
	
	protected Consumer<String> logger;
	protected BiConsumer<String, ClientHandler> receiver;
	protected Consumer<ClientHandler> sessionStopper;
	protected BiConsumer<ClientHandler, IOException> errorRecuperator;
	protected Object receiverArg;
	
	private CountDownLatch active;
	private Socket clientSocket;
	PrintWriter out;
    BufferedReader in;
    
    private Thread clientThread = null;
	
	ClientHandler(Socket client, Consumer<String> logger, Consumer<ClientHandler> sessionStopper, BiConsumer<ClientHandler, IOException> errorRecuperator){
		this.clientSocket = client;
		this.logger= logger;
		this.sessionStopper = sessionStopper;
		this.errorRecuperator = errorRecuperator;
	}
	
	private void logln(String ls) {
    	logger.accept(String.format("%s\n", ls));
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
		            while ((inputLine = in.readLine()) != null && !Thread.currentThread().isInterrupted()) {
		                receiver.accept(inputLine, self);
		            }
		            
		            in.close();
		            out.close();
		            sessionStopper.accept(self);
		        } catch (IOException e) {
		            logln(String.format("[!] ClientHandler error: %s", e.getMessage()));
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
		} catch (IOException e) {
            logln(String.format("[>] ClientHandler stop: %s", e.getMessage()));
        }
		clientThread.interrupt();
	}
	
	public void send(String data) {
		out.print(data+"\n");
		out.flush();
	}


}
