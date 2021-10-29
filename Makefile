export LD_LIBRARY_PATH=./
CXX = g++
CC= gcc
all:
	 ${CXX} -o test Test_ESPPTAT.cpp espptat.cpp bn_pair.cpp   miracl.a -O2 
clean:
	rm -f test
