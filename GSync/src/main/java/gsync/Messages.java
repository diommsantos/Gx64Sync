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
		public String modHash;
		public long rva;
		public String comment;
		
		public Comment() {} public Comment(String modHash, long rva, String cmmt) {this.modHash = modHash; this.rva = rva; this.comment = cmmt;}
	}
	
	public static class Session extends Message{
		public static String id = "session";
		public String sessionName;
		public String programName;
		
		public Session(){} public Session(String sessionName, String programName) {this.sessionName = sessionName; this.programName = programName;}
	}
	
	public static class DebuggerCmd extends Message{
		public enum CMDTYPE{RUN, PAUSE, STEPINTO, STEPOVER, BREAKPOINT}
		public static String id = "dbgcmd";
		public CMDTYPE cmdType;
		public String modHash;
		public long rva;
		
		public DebuggerCmd(){} public DebuggerCmd(CMDTYPE cmdType, String modHash, long rva){this.cmdType = cmdType; this.modHash = modHash; this.rva = rva;}
		
	}
	
	public static class SessionStatus extends Message{
		public enum SESSIONSTATUS{RUNNING, PAUSED, NOPROGRAM}
		public static String id = "dbgsession";
		SESSIONSTATUS status;
		public String programPath;
		
		public SessionStatus(){} public SessionStatus(SESSIONSTATUS status, String modPath) {this.status = status; this.programPath = modPath;}
	}
	
	public static class HyperSyncState extends Message{
	    public static String id = "hysyncstate";
	    public boolean state;
	    
	    public HyperSyncState(){} public HyperSyncState(boolean state) {this.state = state;}
	}
	
	public static class RelativeAddress extends Message{
		public static String id = "rva";
		public String modName;
		public String modHash;
		public long rva;
		
		public RelativeAddress() {} public RelativeAddress(String modName, String modHash, long rva) {this.modName = modName; this.modHash = modHash; this.rva = rva;} 
	}
}
