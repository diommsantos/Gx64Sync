package gsync;

import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
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
	
	//SyncHandler State callback
	protected List<Runnable> startCallbacks = new ArrayList<Runnable>();
	protected List<Runnable> stopCallbacks = new ArrayList<Runnable>();
	protected List<Runnable> errorCallbacks = new ArrayList<Runnable>();
	protected List<Consumer<Integer>> clientHandlerErrorsCallbacks = new ArrayList<Consumer<Integer>>();
	protected List<Consumer<Integer>> sessionStartCallbacks = new ArrayList<Consumer<Integer>>();
	protected List<Consumer<Integer>> sessionStopCallbacks = new ArrayList<Consumer<Integer>>();
	
	protected Listener listener;
	protected int nextSessionHandle = 0;
	protected SortedMap<Integer, ClientHandler> sessions = new TreeMap<Integer, ClientHandler>();
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
	
	public void installStartCallback(Runnable callback) {
		startCallbacks.add(callback);
	}
	
	public void installStopCallbacks(Runnable callback) {
		stopCallbacks.add(callback);
	}
	
	public void installErrorCallbacks(Runnable callback) {
		errorCallbacks.add(callback);
	}
	
	public void installClientHandlerErrorsCallbacks(Consumer<Integer> callback) {
		clientHandlerErrorsCallbacks.add(callback);
	}
	
	public void installSessionStartCallbacks(Consumer<Integer> callback) {
		sessionStartCallbacks.add(callback);
	}
	
	public void installSessionStopCallbacks(Consumer<Integer> callback) {
		sessionStopCallbacks.add(callback);
	}
	
	public Set<Integer> getAllSessionHandles(){
		return sessions.keySet();
	}
	
	private Integer getSessionHandle(ClientHandler session) {
		for(Integer key : sessions.keySet()) {
			if(sessions.get(key) == session)
				return key;
		}
		return null;
	}
	
	protected void receiver(String data, ClientHandler session){
		try {
			JSONObject jsonObj = new JSONObject(data);
			String id = jsonObj.getString("id");
			Message messageObj = decode(data, id);
			sessionLock.lock();
			for(BiConsumer<Message, Integer> subscriber: subscribers.get(id))
				subscriber.accept(messageObj, getSessionHandle(session));
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
	
	protected void sessionStopper(ClientHandler session) {
		int index = getSessionHandle(session);
		sessions.remove(index);
		session.stop();
		for(Consumer<Integer> callback : sessionStopCallbacks)
			callback.accept(index);
	}
	
	protected void errorRecuperator(ClientHandler session, IOException e) {
		int index = getSessionHandle(session);
		for(Consumer<Integer> callback : clientHandlerErrorsCallbacks)
			callback.accept(index);
		sessions.remove(index);
		session.stop();
	}
	
	protected void onConnectionAccept(Socket sessionSocket) {
		ClientHandler clientSession = new ClientHandler(sessionSocket, logger, this::sessionStopper, this::errorRecuperator);
		clientSession.installReceiver(this::receiver);
		sessions.put(nextSessionHandle, clientSession);
		clientSession.start();
		for(Consumer<Integer> callback : sessionStartCallbacks) {
			callback.accept(nextSessionHandle);
		}
		 nextSessionHandle++;
	}
	
	public void start() {
		if(active)
			return;
		listener.installOnConnectionAccept(this::onConnectionAccept);
		listener.start();
		active = true;
		for(Runnable callback : startCallbacks)
			callback.run();
	}
	
	public void stop() {
		if(!active)
			return;
		listener.stop();
		for(int index : sessions.keySet()) {
			sessions.get(index).stop();
			for(Consumer<Integer> callback : sessionStopCallbacks) {
				callback.accept(index);
			}
			sessions.remove(index);
		}
		active = false;
		for(Runnable callback : stopCallbacks)
			callback.run();	
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
			sessions.firstEntry().getValue().send(this.encode(message));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
