CC	:= gcc
CFLAGS	:= -g -W
LFLAGS	:= -lpthread
BIN 	:= toyIP
SRCS	:= $(wildcard *.c) # 当前目录下的所有的.c文件 
OBJS	:= $(SRCS:.c=.o)   # 将所有的.c文件名替换为.o

.PHONY: all clean

all:$(BIN)

$(BIN):$(OBJS) 
	@echo "正在链接程序......";
	$(CC) $(CFLAGS) $(OBJS) $(LFLAGS) -o $(BIN)   


clean:
	rm -f *.o
	rm -f $(BIN)
