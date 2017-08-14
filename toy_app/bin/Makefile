include ../Make.defines

# 程序的名称
BINS	:= curl server udp_cli
SRCS	:= $(wildcard *.c)
OBJS	:= $(SRCS:.c=.o)
BINOS	:= $(addsuffix .o, $(BINS))

.PHONY: all clean

all:$(BINS)

$(BINS):$(OBJS) $(LIBS)
	@echo "正在链接程序...."; 
	$(foreach BIN, $@, $(CC) $(CFLAGS) $(BIN).o $(LFLAGS) -o $(BIN) $(LIBS))

%.o:%.c
# gcc的-c表示只编译,不链接
	@echo "正在编译代码....";
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	rm -rf *.o $(BINS)
