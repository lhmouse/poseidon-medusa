#!/bin/bash

export CPPFLAGS+=' -DNDEBUG -std=c++11'
export CXXFLAGS+=' -O2 -g'

mkdir -p m4
autoreconf -if
./configure --enable-shared --disable-static --prefix=/usr/local
