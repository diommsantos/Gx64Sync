package gsync;

import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import org.json.JSONObject;

import com.fasterxml.jackson.jr.ob.JSON;
import com.fasterxml.jackson.jr.ob.JSON.Feature;
import com.fasterxml.jackson.jr.ob.JSONObjectException;


public class SyncHandler {
	
	protected Consumer<String> logger;
	
	protected Listener listener;
	protected List<ClientHandler> sessions = new ArrayList<ClientHandler>();
	protected Lock sessionLock = new ReentrantLock(true);
	
	boolean active = false;
	
	List<String> ids = new ArrayList<String>();
	Map<String, Class<?>> messages;
	
	Map<String, List<BiConsumer<Message, Integer>>> subscribers;
	
	public SyncHandler(Consumer<String> logger){
		this.logger = logger;
		listener = new Listener(logger);
		
		//Initialize the ids list, messages and subscribers maps
		Class<?>[] decMessagesClasses = Messages.class.getDeclaredClasses();
		String id = "";
		messages = new HashMap<String, Class<?>>(decMessagesClasses.length);
		subscribers = new HashMap<String, List<BiConsumer<Message, Integer>>>(decMessagesClasses.length);
		for(int i = 0; i < decMessagesClasses.length; i++ ) {
			try {
				id = (String) decMessagesClasses[i].getDeclaredField("id").get(null);
				ids.add(id);				
				messages.put(id, decMessagesClasses[i]);
				subscribers.put(id, new ArrayList<BiConsumer<Message, Integer>>(5));
			} catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException
					| SecurityException e) {
				e.printStackTrace();
			}
		}
	}
	
	protected void receiver(String data, ClientHandler session){
		try {
			JSONObject jsonObj = new JSONObject(data);
			String id = jsonObj.getString("id");
			Message messageObj = decode(data, id);
			sessionLock.lock();
			for(BiConsumer<Message, Integer> subscriber: subscribers.get(id))
				subscriber.accept(messageObj, sessions.indexOf(session));
			sessionLock.unlock();
		}catch(RuntimeException  e){
			e.printStackTrace();
		}
	}
	
	protected Message decode(String data, String id){
		Class<?> messageClass = messages.get(id);
		Object messageObj = null;
		try {
			messageObj = JSON.std.with(Feature.INCLUDE_STATIC_FIELDS).beanFrom(messageClass, data);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return (Message) messageObj;
	}
	
	protected String encode(Object message) throws JSONObjectException, IOException {
		return JSON.std.with(Feature.INCLUDE_STATIC_FIELDS).asString(message); //Feature.PRESERVE_FIELD_ORDERING doesn't work with static fields -.-' 
	}
	
	protected void errorRecuperator(ClientHandler session, IOException e) {
		sessions.remove(session);
		session.stop();
	}
	
	protected void onConnectionAccept(Socket sessionSocket) {
		ClientHandler clientSession = new ClientHandler(sessionSocket, logger, this::errorRecuperator);
		clientSession.installReceiver(this::receiver);
		sessions.add(clientSession);
		clientSession.start();
	}
	
	public void start() {
		if(active)
			return;
		listener.installOnConnectionAccept(this::onConnectionAccept);
		listener.start();
		active = true;
	}
	
	public void stop() {
		if(!active)
			return;
		listener.stop();
		for(ClientHandler session: sessions) {
			session.stop();
		}
		active = false;
		
	}
	
	@SuppressWarnings("unchecked")
	public <MessageType extends Message> int subscribe(Class<?> messageClass, BiConsumer<MessageType, Integer> callback) {
		String id = "";
		try {
			id = (String) messageClass.getDeclaredField("id").get(null);
			subscribers.get(id).add((BiConsumer<Message, Integer>) callback);
			return (subscribers.get(id).size()-1) * ids.size() + ids.indexOf(id); //returns unique subscriber handler
		} catch (IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return -1;
		}
		
	}
	
	public <MessageType extends Message> int subscribe(Class<?> messageClass, Consumer<MessageType> callback) {
		BiConsumer<MessageType, Integer> subscriber = (o, i) -> callback.accept(o);		
		return subscribe(messageClass, subscriber);
	}
	

	public <MessageType extends Message> void unsubscribe(int subscriberHandle) {
		String id = ids.get(subscriberHandle % ids.size());
		subscribers.get(id).remove(subscriberHandle / ids.size());
	}
		
	public void send(Object message, int sessionHandle){
		try {
			sessions.get(sessionHandle).send(this.encode(message));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void send(Object message){
		try {
			sessions.get(0).send(this.encode(message));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
