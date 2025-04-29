After installing the full msys2, run in the x64 terminal the following commands:

export PATH=/mingw64/bin:$PATH
g++ -O3 -march=native -I /mingw64/include -I /mingw64/include/openssl -L /mingw64/lib keyhunter.cpp -o keyhunter.exe -lssl -lcrypto -lsecp256k1 -lpthread

surely inside the terminal embedded on vscode, given the proper configuration.
