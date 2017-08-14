include ../Make.defines
LIB_OBJS	:= liblevelip.o

# 伪目标
.PHONY: all clean

all:	$(LIB_OBJS)
# 下面的命令主要是用于打包,将LIB_OBJS所代表的文件打包至LIBS(../lib.a)
	@echo "正在打包代码...";
	ar rcs $(LIBS) $(LIB_OBJS)

# 将所有的.c文件编译成.o文件
%.o:%.c
	@echo "正在编译代码...";
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o ../lib.a
