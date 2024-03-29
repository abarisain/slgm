EXEC = slgm
FLAGS = -lldap -DLDAP_DEPRECATED
OBJ = util.c slgm.c main.c
SRC = $(OBJ:.o=.c)
ARGS = $(FLAGS)


all : $(EXEC)


$(EXEC) : $(OBJ)
	gcc -o $@ $^ $(ARGS) $(ARGS_FINAL) $(DEBUG)

.c.o:
	gcc -o $@ -c $< $(ARGS) $(DEBUG)

clean:
	rm -rf *.o

mrproper: clean
	rm -rf $(EXEC)

debug:
	make DEBUG="-g -D DEBUG"

