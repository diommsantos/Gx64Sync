package gsync;

import java.util.function.Consumer;

public class TestSender {
	SyncHandler sh;
	Consumer<String> logger;
	
	public TestSender(SyncHandler syncHndl, Consumer<String> logger) {
		this.sh = syncHndl;
		this.logger = logger;
	}
	
	public void receive(Messages.Test m) {
		logger.accept("Message received: test:"+m.test.toString()+" testInt:"+m.testInt+"\n");
	}
	
	public void send() {
		logger.accept("Test Message sent!\n");
		sh.send(new Messages.Test());
		sh.send(new Messages.Location(1234444));
		sh.subscribe(Messages.Test.class, this::receive);
	}


}
