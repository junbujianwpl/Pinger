TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    Pinger.cpp

HEADERS += \
    Pinger.h


LIBS += -lWS2_32
