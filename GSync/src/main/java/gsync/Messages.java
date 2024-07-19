package gsync;

abstract class Message{
	
}

public class Messages {
		
	public static class Test extends Message{
		public static String id = "test";
		public String test = "test";
		public int testInt = 125;
	}
	
	public static class Location extends Message{
		public static String id = "loc";
		public long loc;
		public Location() {} public Location(long loc) {this.loc = loc;}
	}
	
	public static class Base extends Message{
		public static String id = "base";
		public long base;
		
		public Base() {} public Base(long base) {this.base = base;}
	}
	
	public static class Comment extends Message{
		public static String id = "cmmt";
		public String modname;
		public long rva;
		public String comment;
		
		public Comment() {} public Comment(String modname, long rva, String cmmt) {this.modname = modname; this.rva = rva; this.comment = cmmt;}
	}
	
	public static class Session extends Message{
		public static String id = "session";
		public String sessionName;
		public String programName;
		
		public Session(){} public Session(String sessionName, String programName) {this.sessionName = sessionName; this.programName = programName;}
	}
}
