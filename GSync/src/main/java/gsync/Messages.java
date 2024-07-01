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
}
