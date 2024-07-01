package gsync;

import java.util.function.BiConsumer;
import java.util.function.Consumer;

public class Test {
	
	public Test(BiConsumer<String, Integer> f) {
		f.accept("Inside test!", 100);
	}

}
