package gsync;

import java.util.function.BiConsumer;

public class Test {
	
	public Test(BiConsumer<String, Integer> f) {
		f.accept("Inside test!", 100);
	}

}
