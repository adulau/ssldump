CC=gcc -g -I../../common/include -DYYDEBUG=1
YACC=bison -d -y -v
LEX=flex
OBJS=lex.yy.o y.tab.o main.o

default: all

lex.yy.c: ssl.l
	$(LEX) ssl.l

y.tab.c: ssl.y
	$(YACC) ssl.y

grammar: y.tab.c lex.yy.c
	$(LEX) ssl.l
	$(YACC) ssl.y

all: grammar $(OBJS)
	$(CC) $(OBJS) -L../../common/make/freebsd31  -ly -lm

