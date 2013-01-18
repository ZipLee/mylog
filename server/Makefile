objects = test.o liblog.o

All : $(objects)
	cc -o test $(objects)

test : test.c LibLog.h
	cc -c test.c

LibLog: LibLog.c LibLog.h
	cc -c LibLog.h	

clean:
	rm *.o test Log_*.txt
