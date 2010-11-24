
default: src/fireflood.c
	gcc src/fireflood.c -o bin/a.out
	echo '#!/bin/bash\nsudo ./bin/a.out' > fireflood
	chmod +x fireflood

clean:
	rm -f bin/a.out
	rm -f fireflood
