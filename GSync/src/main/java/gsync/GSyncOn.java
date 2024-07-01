package gsync;

import java.util.function.Consumer;

public class GSyncOn{
	
	SyncHandler sh;
	Consumer<String> logger;
	
	GSyncOn(SyncHandler syncHndl, Consumer<String> logger){
		this.sh = syncHndl;
		this.logger = logger;
	}
	
	public void on() {
		logger.accept("GSync on!\n");
		sh.start();
	}
	
	public void off() {
		logger.accept("GSync off!\n");
		sh.stop();
	}
}
