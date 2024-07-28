package gsync;

import java.io.IOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

import com.fasterxml.jackson.jr.ob.JSON;
import com.fasterxml.jackson.jr.ob.JSON.Feature;
import com.fasterxml.jackson.jr.ob.JSONObjectException;


public class SyncHandler {
	
	protected Logger rawLogger;
	protected Logger logger;
	
	boolean active = false;
	
	//SyncHandler State callbacks
	protected List<Runnable> startCallbacks = new ArrayList<Runnable>();
	protected List<Runnable> stopCallbacks = new ArrayList<Runnable>();
	protected List<Runnable> errorCallbacks = new ArrayList<Runnable>();
	protected List<Consumer<Integer>> clientHandlerErrorsCallbacks = new ArrayList<Consumer<Integer>>();
	protected List<Consumer<Integer>> sessionStartCallbacks = new ArrayList<Consumer<Integer>>();
	protected List<Consumer<Integer>> sessionStopCallbacks = new ArrayList<Consumer<Integer>>();
	
	protected Listener listener;
	
	protected int lastActiveSessionHandle = 0;
	protected TreeMap<Integer, ClientHandler> sessions = new TreeMap<Integer, ClientHandler>();
	protected Lock sessionLock = new ReentrantLock(true);
	
	List<String> ids = new ArrayList<String>();
	Map<String, Class<?>> messages;
	Map<String, SortedMap<Integer, BiConsumer<Message, Integer>>> subscribers;
	
	public SyncHandler(Logger logger){
		this.rawLogger = logger;
		SyncHandler self = this;
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
		listener = new Listener(rawLogger);
		this.installClientHandlerErrorsCallbacks((sessionHandle) -> {
			if(lastActiveSessionHandle == sessionHandle)
				lastActiveSessionHandle = sessions.lastKey();
		});
		this.installSessionStopCallbacks((sessionHandle) -> {
			if(lastActiveSessionHandle == sessionHandle)
				lastActiveSessionHandle = sessions.lastKey();
		});
		
		//Initialize the ids list, messages and subscribers maps
		Class<?>[] decMessagesClasses = Messages.class.getDeclaredClasses();
		String id = "";
		messages = new HashMap<String, Class<?>>(decMessagesClasses.length);
		subscribers = new HashMap<String, SortedMap<Integer, BiConsumer<Message, Integer>>>(decMessagesClasses.length);
		for(int i = 0; i < decMessagesClasses.length; i++ ) {
			try {
				id = (String) decMessagesClasses[i].getDeclaredField("id").get(null);
				ids.add(id);				
				messages.put(id, decMessagesClasses[i]);
				subscribers.put(id, new TreeMap<Integer, BiConsumer<Message, Integer>>());
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
	
	public NavigableSet<Integer> getAllSessionHandles(){
		return new TreeSet<Integer>(sessions.navigableKeySet());
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
			Map<String, Object> jsonMap = JSON.std.mapFrom(data);
			String id = (String) jsonMap.get("id");
			Message messageObj = decode(data, id);
			sessionLock.lock();
			lastActiveSessionHandle = getSessionHandle(session);
			for(BiConsumer<Message, Integer> subscriber: subscribers.get(id).values())
				subscriber.accept(messageObj, lastActiveSessionHandle);
			sessionLock.unlock();
		}catch(IOException  e){
			logger.loglnError(e.getMessage());
			for(Runnable callback : errorCallbacks)
				callback.run();
		}
	}
	
	protected Message decode(String data, String id) throws JSONObjectException, IOException{
		Class<?> messageClass = messages.get(id);
		Object messageObj = JSON.std.with(Feature.INCLUDE_STATIC_FIELDS).beanFrom(messageClass, data);
		return (Message) messageObj;
	}
	
	protected String encode(Object message) throws JSONObjectException, IOException {
		return JSON.std.with(Feature.INCLUDE_STATIC_FIELDS).asString(message); //Feature.PRESERVE_FIELD_ORDERING doesn't work with static fields -.-' 
	}
	
	protected void sessionStopper(ClientHandler session) {
		int index = getSessionHandle(session);
		for(Consumer<Integer> callback : sessionStopCallbacks)
			callback.accept(index);
		sessions.remove(index);
		session.stop();
	}
	
	protected void errorRecuperator(ClientHandler session, IOException e) {
		int index = getSessionHandle(session);
		for(Consumer<Integer> callback : clientHandlerErrorsCallbacks)
			callback.accept(index);
		sessions.remove(index);
		session.stop();
	}
	
	protected void onConnectionAccept(Socket sessionSocket) {
		ClientHandler clientSession = new ClientHandler(sessionSocket, rawLogger, this::sessionStopper, this::errorRecuperator);
		clientSession.installReceiver(this::receiver);
		int sessionHandle = sessions.isEmpty() ? 0 : sessions.lastKey()+1; 
 		sessions.put(sessionHandle, clientSession);
		clientSession.start();
		for(Consumer<Integer> callback : sessionStartCallbacks) {
			callback.accept(sessionHandle);
		}
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
			int subscriberHandle = subscribers.get(id).isEmpty() ? ids.indexOf(id) : subscribers.get(id).lastKey()+ids.size();
			subscribers.get(id).put(subscriberHandle, (BiConsumer<Message, Integer>) callback);
			return subscriberHandle; //returns unique subscriber handler
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
		subscribers.get(id).remove(subscriberHandle);
	}
		
	public void send(Object message, int sessionHandle){
		try {
			sessions.get(sessionHandle).send(this.encode(message));
		} catch(NullPointerException e) {
			logger.loglnError("The provided sessionHandle is not a valid handle. "+
							  "Please verify if you are connected to an active debugging session.");
		}
		catch (IOException e) {
			logger.loglnError(e.getMessage());
		}
		
	}
	
	public void send(Object message){
			send(message, lastActiveSessionHandle);
	}
}
