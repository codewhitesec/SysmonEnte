CC := x86_64-w64-mingw32-gcc
CXX := x86_64-w64-mingw32-g++
LD := x86_64-w64-mingw32-ld
CFLAGS := -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 


#SysmonEnte
S_SRCSENTE := src/SysmonEnte/adjuststack.asm src/SysmonEnte/chkstk.asm src/SysmonEnte/gatetrampolin.asm 
C_SRCSENTE := src/SysmonEnte/apiresolve.c src/SysmonEnte/main.c src/SysmonEnte/injection.c src/SysmonEnte/misc.c src/SysmonEnte/recycledgate.c src/SysmonEnte/threads.c src/SysmonEnte/token.c
OBJSENTE := $(patsubst src/SysmonEnte/%.asm,src/SysmonEnte/%.o,$(S_SRCSENTE)) $(patsubst src/SysmonEnte/%.c,src/SysmonEnte/%.o,$(C_SRCSENTE))
CCLDFLAGSENTE := -Wl,-Tsrc/SysmonEnte/linker.ld,--no-seh -DC2

#Kueken
S_SRCSKUEKEN := src/Kueken/adjuststack.asm src/Kueken/chkstk.asm
C_SRCSKUEKEN := src/Kueken/apiresolve.c src/Kueken/main.c 
OBJSKUEKEN := $(patsubst src/Kueken/%.asm,src/Kueken/%.o,$(S_SRCSKUEKEN)) $(patsubst src/Kueken/%.c,src/Kueken/%.o,$(C_SRCSKUEKEN))
CCLDFLAGSKUEKEN := -Wl,-Tsrc/Kueken/linker.ld,--no-seh -DC2

all: bin/Kueken.exe bin/Kueken.bin src/SysmonEnte/kueken.h bin/SysmonEnte.exe bin/SysmonEnte.bin bin/EntenLoader.exe

bin/Kueken.exe: $(OBJSKUEKEN)
	$(LD) -s $^ -o $@

bin/Kueken.bin: bin/Kueken.exe
	objcopy -j .text -O binary $< $@

src/Kueken/%.o: src/Kueken/%.asm
	nasm -f win64 $< -o $@

src/Kueken/%.o: src/Kueken/%.c
	$(CC) $< $(CFLAGS) -c -o $@ $(CCLDFLAGSKUEKEN)

bin/SysmonEnte.exe: $(OBJSENTE) 
	$(LD) -s $^ -o $@

bin/SysmonEnte.bin: bin/SysmonEnte.exe
	objcopy -j .text -O binary $< $@

src/SysmonEnte/%.o: src/SysmonEnte/%.asm
	nasm -f win64 $< -o $@

src/SysmonEnte/%.o: src/SysmonEnte/%.c
	$(CC) $< $(CFLAGS) -c -o $@ $(CCLDFLAGSENTE)

src/SysmonEnte/kueken.h: bin/Kueken.bin
		(                                                         \
				set -e;                                            \
				cat src/SysmonEnte/kueken.h.prefix; 	      \
				python3 helpers/convertToHex.py $< | xargs -i echo '{}';\
				echo ';'                                         \
		) > $@.t
		mv $@.t $@

src/EntenLoader/SysmonEnte.h: bin/SysmonEnte.bin
		(                                                         \
				set -e;                                            \
				cat src/EntenLoader/SysmonEnte.h.prefix; 	      \
				python3 helpers/convertToHex.py $< | xargs -i echo '{}';\
				echo ';'                                         \
		) > $@.t
		mv $@.t $@

bin/EntenLoader.exe: src/EntenLoader/EntenLoader.cpp src/EntenLoader/SysmonEnte.h
	$(CXX) -s -o $@ $< -municode
	rm bin/Kueken.exe bin/Kueken.bin bin/SysmonEnte.exe

.PHONY: clean
clean:
	rm -rf $(OBJSENTE) $(OBJSKUEKEN) \
		bin/Kueken.exe bin/Kueken.bin bin/SysmonEnte.exe bin/SysmonEnte.bin src/EntenLoader/SysmonEnte.h bin/EntenLoader.exe src/SysmonEnte/kueken.h
