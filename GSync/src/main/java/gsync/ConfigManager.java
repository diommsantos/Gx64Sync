package gsync;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

import com.fasterxml.jackson.jr.ob.JSON;

public class ConfigManager {
	Logger logger;
	
	static boolean active = false;
	static Path configFilePath;
	static Map<String, Object> config;
	static IOException configException = null;
	
	public ConfigManager(Logger logger) {
		if(active)
			return;
		ConfigManager self = this;
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
        
        if(configException == null)
			this.logger.logln("Using configurations from the " + configFilePath.toString() +" file.");
        else if (configException instanceof NoSuchFileException)
			this.logger.logln(String.format("Config file %s not found. Using default configurations.", ((NoSuchFileException) configException).getFile()));
        else
			this.logger.loglnError(configException.getMessage());
        active = true;
	}
	
	static {
		try {
			configFilePath = Paths.get(System.getProperty("user.home"), "config.sync");
	    	InputStream configInputStream = Files.newInputStream(configFilePath);
			config = JSON.std.mapFrom(configInputStream);
			configInputStream.close();
		} catch (IOException e) {
			configException = e;
		}
		
	}
	
	@SuppressWarnings("unchecked")
	public static <valueType> valueType getConfig(String key){
		if(config == null)
			return null;
		return (valueType) config.get(key);
	}
	
	public static <valueType> valueType getConfig(String key, valueType defaultValue) {
		valueType value = getConfig(key);
		return value == null ? defaultValue : value;
	}
	
}
